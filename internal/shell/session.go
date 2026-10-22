// Package shell provides the stateful command loop independently of the CLI.
package shell

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ml0renz0/secretwright/internal/vault"
)

const historyLimit = 100

// Editor provides either terminal editing or a stream of command lines.
type Editor interface {
	ReadLine(context.Context, string) (string, error)
	ReplaceHistory([]string) error
	Close() error
}

// Result carries the exit code and, only after a successful cd, its new path.
type Result struct {
	Code int
	CWD  string
}

// Executor runs the same command implementation used by the direct CLI.
type Executor func(context.Context, []string, string, io.Reader, io.Writer, io.Writer) Result

type Options struct {
	Interactive bool
	State       *State
	Interrupts  <-chan os.Signal
}

// State owns the canonical directory, last exit code and approved RAM history.
// Getters return snapshots so completion and terminal editing can read safely.
type State struct {
	mu      sync.RWMutex
	cwd     string
	code    int
	history []string
}

func NewState(cwd string) (*State, error) {
	if cwd == "" {
		cwd = "/"
	}
	if !strings.HasPrefix(cwd, "/") {
		return nil, vault.ErrInvalidPath
	}
	canonical, err := vault.ResolvePath("/", cwd)
	if err != nil {
		return nil, err
	}
	return &State{cwd: canonical, history: []string{}}, nil
}

func (s *State) Directory() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cwd
}

func (s *State) Status() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.code
}

func (s *State) History() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string{}, s.history...)
}

func (s *State) setStatus(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.code = code
}

func (s *State) setDirectory(cwd string) error {
	if !strings.HasPrefix(cwd, "/") {
		return vault.ErrInvalidPath
	}
	canonical, err := vault.ResolvePath("/", cwd)
	if err != nil || canonical != cwd {
		return vault.ErrInvalidPath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cwd = canonical
	return nil
}

func (s *State) remember(args []string) bool {
	line, ok := SafeHistory(args)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.history) != 0 && s.history[len(s.history)-1] == line {
		return false
	}
	s.history = append(s.history, line)
	if len(s.history) > historyLimit {
		s.history = append([]string{}, s.history[len(s.history)-historyLimit:]...)
	}
	return true
}

// Run executes one session. A prompt interrupt does not end an interactive
// session; an operation interrupt cancels only that operation's child context.
func Run(ctx context.Context, editor Editor, execute Executor, stdout, stderr io.Writer, options Options) (code int) {
	if editor == nil || stdout == nil || stderr == nil {
		return 1
	}
	state := options.State
	if state == nil {
		state = &State{cwd: "/", history: []string{}}
	}
	var closeOnce sync.Once
	var closeErr error
	closeEditor := func() {
		closeOnce.Do(func() { closeErr = editor.Close() })
	}
	stopWatch := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			closeEditor()
		case <-stopWatch:
		}
	}()
	defer func() {
		close(stopWatch)
		closeEditor()
		<-watchDone
		if ctx.Err() != nil {
			state.setStatus(130)
			code = 130
		} else if closeErr != nil {
			state.setStatus(1)
			code = shellFailure(stderr, "could not close shell input")
		}
	}()
	for {
		if ctx.Err() != nil {
			state.setStatus(130)
			return 130
		}
		prompt := ""
		if options.Interactive {
			prompt = fmt.Sprintf("[%d] secretwright:%s> ", state.Status(), state.Directory())
		}
		line, err := editor.ReadLine(ctx, prompt)
		// Clear temporary edits and rejected input from the editing library even
		// when the read ends with an interrupt, an oversized line or EOF.
		historyErr := editor.ReplaceHistory(state.History())
		if ctx.Err() != nil {
			state.setStatus(130)
			return 130
		}
		if historyErr != nil {
			state.setStatus(1)
			return shellFailure(stderr, "could not update shell history")
		}
		if errors.Is(err, io.EOF) {
			return state.Status()
		}
		if errors.Is(err, ErrInterrupt) {
			state.setStatus(130)
			if options.Interactive {
				continue
			}
			return 130
		}
		if err != nil {
			state.setStatus(1)
			if errors.Is(err, ErrInvalidLine) {
				if _, writeErr := fmt.Fprintln(stderr, "secretwright: invalid shell command"); writeErr != nil {
					return 1
				}
				if options.Interactive {
					continue
				}
				return 1
			}
			if errors.Is(err, ErrLineTooLong) {
				if _, writeErr := fmt.Fprintln(stderr, "secretwright: shell command exceeds the line size limit"); writeErr != nil {
					return 1
				}
				if options.Interactive {
					continue
				}
				return 1
			}
			return shellFailure(stderr, "could not read shell input")
		}
		args, err := Parse(line)
		if err != nil {
			state.setStatus(1)
			if _, writeErr := fmt.Fprintln(stderr, "secretwright: invalid shell command"); writeErr != nil {
				return 1
			}
			if options.Interactive {
				continue
			}
			return 1
		}
		if len(args) == 0 {
			continue
		}
		if args[0] == "exit" || args[0] == "quit" {
			if len(args) == 1 {
				return state.Status()
			}
			state.setStatus(1)
			if _, err := fmt.Fprintln(stderr, "secretwright: invalid shell command options"); err != nil {
				return 1
			}
			if options.Interactive {
				continue
			}
			return 1
		}
		result := Result{}
		switch args[0] {
		case "pwd", "history":
			if len(args) != 1 {
				if _, err := fmt.Fprintln(stderr, "secretwright: invalid shell command options"); err != nil {
					state.setStatus(1)
					return 1
				}
				result.Code = 1
				break
			}
			var value any = state.History()
			if args[0] == "pwd" {
				value = struct {
					Path string `json:"path"`
				}{Path: state.Directory()}
			}
			if err := json.NewEncoder(stdout).Encode(value); err != nil {
				state.setStatus(1)
				return shellFailure(stderr, "could not write shell output")
			}
		default:
			if execute == nil {
				state.setStatus(1)
				return shellFailure(stderr, "command execution is unavailable")
			}
			result = runCommand(ctx, execute, args, state.Directory(), stdout, stderr, options.Interrupts)
		}
		if ctx.Err() != nil {
			state.setStatus(130)
			return 130
		}
		if result.Code < 0 || result.Code > 255 {
			result.Code = 1
		}
		if result.Code == 0 && result.CWD != "" && args[0] == "cd" {
			if err := state.setDirectory(result.CWD); err != nil {
				if _, err := fmt.Fprintln(stderr, "secretwright: command returned an invalid shell directory"); err != nil {
					state.setStatus(1)
					return 1
				}
				result.Code = 1
			}
		}
		state.setStatus(result.Code)
		if result.Code == 0 && state.remember(args) {
			if err := editor.ReplaceHistory(state.History()); err != nil {
				state.setStatus(1)
				return shellFailure(stderr, "could not update shell history")
			}
		}
		if result.Code != 0 && !options.Interactive {
			return result.Code
		}
	}
}

func runCommand(ctx context.Context, execute Executor, args []string, cwd string, stdout, stderr io.Writer, interrupts <-chan os.Signal) Result {
	// An external signal received while at the prompt must not cancel a later
	// command. Physical prompt Ctrl-C is handled by the editor itself.
	for interrupts != nil {
		select {
		case _, ok := <-interrupts:
			if !ok {
				interrupts = nil
			}
		default:
			goto drained
		}
	}
drained:
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := make(chan struct{})
	finished := make(chan struct{})
	var interrupted atomic.Bool
	go func() {
		defer close(finished)
		select {
		case _, ok := <-interrupts:
			if ok {
				interrupted.Store(true)
				cancel()
			}
		case <-ctx.Done():
			cancel()
		case <-stop:
		}
	}()
	result := execute(child, args, cwd, strings.NewReader(""), stdout, stderr)
	close(stop)
	<-finished
	if interrupted.Load() || ctx.Err() != nil {
		return Result{Code: 130}
	}
	return result
}

func shellFailure(stderr io.Writer, message string) int {
	if _, err := fmt.Fprintln(stderr, "secretwright: "+message); err != nil {
		return 1
	}
	return 1
}
