package shell

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/chzyer/readline"
)

var (
	errTerminalRequired = errors.New("interactive shell requires terminal input and output")
	errTerminalInput    = errors.New("could not read interactive shell input")
	errTerminalOutput   = errors.New("could not write interactive shell output")
	errTerminalMode     = errors.New("could not configure the interactive terminal")
	errTerminalRestore  = errors.New("could not restore the interactive terminal")
)

type terminalEditor struct {
	instance *readline.Instance
	input    *readline.CancelableStdin
	fd       int

	readMu  sync.Mutex
	lineMu  sync.Mutex
	long    bool
	invalid bool

	modeMu sync.Mutex
	mode   *readline.State
	resize func()

	errMu  sync.Mutex
	err    error
	failed chan struct{}
	closed chan struct{}
	once   sync.Once
	result error
}

// IsTerminal checks the supplied descriptors rather than process-wide defaults.
func IsTerminal(input, output *os.File) bool {
	return input != nil && output != nil &&
		readline.IsTerminal(int(input.Fd())) && readline.IsTerminal(int(output.Fd()))
}

// NewTerminalEditor keeps command editing and prompts on stderr. stdout remains
// available to the command executor for its JSON results.
func NewTerminalEditor(input io.ReadCloser, stdout, stderr io.Writer, complete func([]rune, int) ([][]rune, int)) (Editor, error) {
	inputFile, inputOK := input.(*os.File)
	outputFile, outputOK := stderr.(*os.File)
	if !inputOK || !outputOK || !IsTerminal(inputFile, outputFile) {
		return nil, errTerminalRequired
	}
	e := &terminalEditor{
		fd:     int(inputFile.Fd()),
		failed: make(chan struct{}),
		closed: make(chan struct{}),
	}
	e.input = readline.NewCancelableStdin(&terminalInput{editor: e, reader: bufio.NewReader(input)})
	output := terminalWriter{editor: e, target: stderr}
	config := &readline.Config{
		Stdin:                  e.input,
		Stdout:                 output,
		Stderr:                 output,
		HistoryFile:            "",
		HistoryLimit:           historyLimit,
		DisableAutoSaveHistory: true,
		InterruptPrompt:        "\n",
		EOFPrompt:              "\n",
		AutoComplete:           terminalCompleter(complete),
		FuncIsTerminal:         func() bool { return true },
		FuncMakeRaw:            e.enterRaw,
		FuncExitRaw:            e.exitRaw,
		FuncGetWidth: func() int {
			width, _, err := readline.GetSize(int(outputFile.Fd()))
			if err != nil || width <= 0 {
				return 80
			}
			return width
		},
		// Refresh dimensions between reads without installing process-wide
		// signal handlers that outlive this editor.
		FuncOnWidthChanged: func(resize func()) { e.resize = resize },
		FuncFilterInputRune: func(character rune) (rune, bool) {
			// Suspension and command cancellation belong to the session owner.
			return character, character != readline.CharCtrlZ
		},
	}
	config.SetListener(e.limitLine)
	instance, err := readline.NewEx(config)
	if err != nil {
		_ = e.input.Close()
		return nil, errTerminalMode
	}
	e.instance = instance
	return e, nil
}

func (e *terminalEditor) ReadLine(ctx context.Context, prompt string) (string, error) {
	e.readMu.Lock()
	defer e.readMu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	select {
	case <-e.closed:
		return "", io.EOF
	default:
	}
	if err := e.failure(); err != nil {
		return "", err
	}
	e.lineMu.Lock()
	e.long = false
	e.invalid = false
	e.lineMu.Unlock()
	e.instance.SetPrompt(prompt)
	if e.resize != nil {
		e.resize()
	}
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			_ = e.Close()
		case <-e.failed:
			_ = e.Close()
		case <-e.closed:
		case <-done:
		}
	}()
	line, err := e.instance.Readline()
	close(done)
	<-stopped
	if contextErr := ctx.Err(); contextErr != nil {
		return "", contextErr
	}
	if failure := e.failure(); failure != nil {
		return "", failure
	}
	if errors.Is(err, readline.ErrInterrupt) {
		return "", ErrInterrupt
	}
	e.lineMu.Lock()
	tooLong, invalidLine := e.long, e.invalid
	e.lineMu.Unlock()
	if invalidLine {
		return "", ErrInvalidLine
	}
	if errors.Is(err, io.EOF) {
		return "", io.EOF
	}
	if err != nil {
		return "", errTerminalInput
	}
	if tooLong || len(line) > MaxLineBytes {
		return "", ErrLineTooLong
	}
	return line, nil
}

// ReplaceHistory removes readline's temporary edits as well as its committed
// entries. SaveHistory alone can otherwise save a recalled entry's temporary
// buffer instead of the approved argument supplied by the application.
func (e *terminalEditor) ReplaceHistory(lines []string) error {
	e.readMu.Lock()
	defer e.readMu.Unlock()
	select {
	case <-e.closed:
		return nil
	default:
	}
	if err := e.failure(); err != nil {
		return err
	}
	if len(lines) > historyLimit {
		lines = lines[len(lines)-historyLimit:]
	}
	for _, line := range lines {
		if len(line) > MaxLineBytes {
			return ErrLineTooLong
		}
		if !utf8.ValidString(line) || strings.ContainsAny(line, "\r\n\x00") {
			return ErrInvalidLine
		}
	}
	e.instance.ResetHistory()
	for _, line := range lines {
		if line == "" {
			continue
		}
		if err := e.instance.SaveHistory(line); err != nil {
			return errors.New("could not update interactive shell history")
		}
	}
	return nil
}

func (e *terminalEditor) Close() error {
	e.once.Do(func() {
		close(e.closed)
		// readline's FillableStdin closes only its private pipe. Close the
		// cancelable wrapper first so its terminal input goroutine can stop;
		// the caller's underlying stdin remains open.
		if err := e.input.Close(); err != nil {
			e.result = errTerminalInput
		}
		if err := e.instance.Close(); err != nil && e.result == nil {
			e.result = errTerminalRestore
		}
	})
	return e.result
}

func (e *terminalEditor) limitLine(line []rune, position int, key rune) ([]rune, int, bool) {
	e.lineMu.Lock()
	defer e.lineMu.Unlock()
	if !e.long {
		bytes := 0
		for _, character := range line {
			bytes += utf8.RuneLen(character)
			if bytes > MaxLineBytes {
				e.long = true
				break
			}
		}
	}
	if e.long || e.invalid {
		// Discard the entire physical line until Enter or an interrupt. The
		// retained error flag prevents executing a shortened command prefix.
		return nil, 0, true
	}
	return line, position, false
}

func (e *terminalEditor) enterRaw() error {
	e.modeMu.Lock()
	defer e.modeMu.Unlock()
	select {
	case <-e.closed:
		return io.EOF
	default:
	}
	if e.mode != nil {
		return nil
	}
	mode, err := readline.MakeRaw(e.fd)
	if err != nil {
		e.fail(errTerminalMode)
		return errTerminalMode
	}
	e.mode = mode
	return nil
}

func (e *terminalEditor) exitRaw() error {
	e.modeMu.Lock()
	defer e.modeMu.Unlock()
	if e.mode == nil {
		return nil
	}
	if err := readline.Restore(e.fd, e.mode); err != nil {
		e.fail(errTerminalRestore)
		return errTerminalRestore
	}
	e.mode = nil
	return nil
}

func (e *terminalEditor) fail(err error) {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	if e.err == nil {
		e.err = err
		close(e.failed)
	}
}

func (e *terminalEditor) failure() error {
	e.errMu.Lock()
	defer e.errMu.Unlock()
	return e.err
}

type terminalWriter struct {
	editor *terminalEditor
	target io.Writer
}

// Decode only the rune requested by readline. This preserves interactive
// editing and associates malformed input with its physical command line,
// even when the caller pasted several lines in one underlying Read.
type terminalInput struct {
	editor    *terminalEditor
	reader    *bufio.Reader
	remaining []byte
}

func (r *terminalInput) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if len(r.remaining) == 0 {
		character, width, err := r.reader.ReadRune()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				select {
				case <-r.editor.closed:
				default:
					r.editor.fail(errTerminalInput)
				}
			}
			return 0, err
		}
		if (character == utf8.RuneError && width == 1) || character == 0 {
			r.editor.lineMu.Lock()
			r.editor.invalid = true
			r.editor.lineMu.Unlock()
			// readline interprets rune zero as EOF, which could otherwise
			// submit the valid prefix before a malformed byte or NUL.
			character = utf8.RuneError
		}
		r.remaining = []byte(string(character))
	}
	n := copy(data, r.remaining)
	r.remaining = r.remaining[n:]
	return n, nil
}

func (w terminalWriter) Write(data []byte) (int, error) {
	n, err := w.target.Write(data)
	if err != nil || n != len(data) {
		w.editor.fail(errTerminalOutput)
		return n, errTerminalOutput
	}
	return n, nil
}

type terminalCompleter func([]rune, int) ([][]rune, int)

func (complete terminalCompleter) Do(line []rune, position int) (candidates [][]rune, prefix int) {
	if complete == nil {
		return nil, 0
	}
	defer func() {
		if recover() != nil {
			candidates, prefix = nil, 0
		}
	}()
	return complete(line, position)
}
