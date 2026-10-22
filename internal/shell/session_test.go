package shell_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/shell"
)

type editorStep struct {
	line   string
	err    error
	before func()
}

type fakeEditor struct {
	mu         sync.Mutex
	steps      []editorStep
	index      int
	prompts    []string
	histories  [][]string
	historyErr error
	closed     bool
	closeCount int
}

func (e *fakeEditor) ReadLine(ctx context.Context, prompt string) (string, error) {
	e.mu.Lock()
	e.prompts = append(e.prompts, prompt)
	if e.index >= len(e.steps) {
		e.mu.Unlock()
		return "", io.EOF
	}
	step := e.steps[e.index]
	e.index++
	e.mu.Unlock()
	if step.before != nil {
		step.before()
	}
	return step.line, step.err
}

func (e *fakeEditor) ReplaceHistory(values []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.histories = append(e.histories, append([]string(nil), values...))
	return e.historyErr
}

func (e *fakeEditor) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.closed {
		e.closed = true
		e.closeCount++
	}
	return nil
}

func newTestState(t *testing.T, cwd string) *shell.State {
	t.Helper()
	state, err := shell.NewState(cwd)
	if err != nil {
		t.Fatalf("initialize session state: %v", err)
	}
	return state
}

func noOpExecute(context.Context, []string, string, io.Reader, io.Writer, io.Writer) shell.Result {
	return shell.Result{}
}

func TestSessionKeepsDirectoryOnlyAfterSuccessfulCD(t *testing.T) {
	state := newTestState(t, "/secret")
	editor := &fakeEditor{steps: []editorStep{
		{line: "cd app"}, {line: "cd denied"}, {line: "pwd"}, {line: "ls child"}, {line: "exit"},
	}}
	var commands [][]string
	var directories []string
	execute := func(ctx context.Context, args []string, cwd string, stdin io.Reader, stdout, stderr io.Writer) shell.Result {
		commands = append(commands, append([]string(nil), args...))
		directories = append(directories, cwd)
		body, err := io.ReadAll(stdin)
		if err != nil || len(body) != 0 {
			t.Error("command execution acquired the session command stream")
		}
		if args[0] == "cd" && args[1] == "app" {
			return shell.Result{CWD: "/secret/app"}
		}
		if args[0] == "cd" {
			return shell.Result{Code: 2, CWD: "/unconfirmed"}
		}
		return shell.Result{}
	}
	var stdout, stderr bytes.Buffer
	if code := shell.Run(context.Background(), editor, execute, &stdout, &stderr, shell.Options{Interactive: true, State: state}); code != 0 {
		t.Fatalf("interactive session returned %d", code)
	}
	if state.Directory() != "/secret/app" || !reflect.DeepEqual(directories, []string{"/secret", "/secret/app", "/secret/app"}) {
		t.Error("failed directory change altered the session or relative command directory")
	}
	if len(commands) != 3 || commands[2][0] != "ls" {
		t.Error("session builtins were sent to the command executor")
	}
	var pwd map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &pwd); err != nil || pwd["path"] != "/secret/app" {
		t.Error("pwd did not report the validated session directory as JSON")
	}
	if !strings.Contains(strings.Join(editor.prompts, "\n"), "[2] secretwright:/secret/app> ") {
		t.Error("prompt lost the last failure status or current directory")
	}
	if editor.closeCount != 1 {
		t.Error("session did not release its editor")
	}
}

func TestBatchStopsAtFirstErrorWithoutPromptOrFollowingMutation(t *testing.T) {
	for _, failedCode := range []int{1, 2, 3, 4, 5} {
		state := newTestState(t, "/")
		editor := &fakeEditor{steps: []editorStep{{line: "cat /secret/missing"}, {line: "rm --force /legacy/never-run"}}}
		var calls int
		execute := func(context.Context, []string, string, io.Reader, io.Writer, io.Writer) shell.Result {
			calls++
			return shell.Result{Code: failedCode}
		}
		var stdout, stderr bytes.Buffer
		code := shell.Run(context.Background(), editor, execute, &stdout, &stderr, shell.Options{State: state})
		if code != failedCode || state.Status() != failedCode || calls != 1 {
			t.Errorf("batch failure code %d became %d after %d commands", failedCode, code, calls)
		}
		for _, prompt := range editor.prompts {
			if prompt != "" {
				t.Error("batch session requested an interactive prompt")
			}
		}
	}
}

func TestSessionDoesNotExecuteMalformedLinesOrStorePrivateHistory(t *testing.T) {
	state := newTestState(t, "/")
	editor := &fakeEditor{steps: []editorStep{
		{line: " # comment"}, {line: ""}, {line: "ls /secret/app"}, {line: "ls /secret/app"},
		{line: "put --file private-file-marker /secret/app"},
		{line: "unknown private-token-marker"}, {line: "cat 'private-json-marker"},
		{line: "cat /secret/private"}, {line: "status --token-file private-token-marker"}, {line: "history"},
	}}
	var executed []string
	execute := func(_ context.Context, args []string, _ string, _ io.Reader, _, _ io.Writer) shell.Result {
		executed = append(executed, args[0])
		if args[0] == "unknown" {
			return shell.Result{Code: 1}
		}
		return shell.Result{}
	}
	var stdout, stderr bytes.Buffer
	if code := shell.Run(context.Background(), editor, execute, &stdout, &stderr, shell.Options{Interactive: true, State: state}); code != 0 {
		t.Errorf("history session returned %d", code)
	}
	if !reflect.DeepEqual(state.History(), []string{"ls /secret/app"}) {
		t.Error("history stored a duplicate, raw rejected line, mutation, or sensitive command")
	}
	if !reflect.DeepEqual(executed, []string{"ls", "ls", "put", "unknown", "cat", "status"}) {
		t.Error("parser executed a malformed line, comment, or history builtin")
	}
	for _, marker := range []string{"private-file-marker", "private-token-marker", "private-json-marker"} {
		if strings.Contains(stdout.String()+stderr.String(), marker) {
			t.Error("history or parser diagnostics exposed private command input")
		}
		for _, history := range editor.histories {
			if strings.Contains(strings.Join(history, "\n"), marker) {
				t.Error("editor searchable history received private raw command input")
			}
		}
	}
	if len(editor.histories) < len(editor.steps)+1 {
		t.Error("editor history was not rebuilt after every input, including rejected lines and EOF")
	}
	copyOfHistory := state.History()
	copyOfHistory[0] = "private-modified-history"
	if state.History()[0] != "ls /secret/app" {
		t.Error("history accessor leaked mutable session storage")
	}
}

func TestHistoryIsBoundedAndDoesNotCrossSessions(t *testing.T) {
	state := newTestState(t, "/")
	steps := make([]editorStep, 0, 125)
	for i := 0; i < 125; i++ {
		steps = append(steps, editorStep{line: "ls /secret/" + strings.Repeat("a", i+1)})
	}
	editor := &fakeEditor{steps: steps}
	execute := func(context.Context, []string, string, io.Reader, io.Writer, io.Writer) shell.Result {
		return shell.Result{}
	}
	if code := shell.Run(context.Background(), editor, execute, io.Discard, io.Discard, shell.Options{Interactive: true, State: state}); code != 0 || len(state.History()) != 100 {
		t.Error("session history was not bounded to its most recent approved entries")
	}
	if fresh := newTestState(t, "/"); len(fresh.History()) != 0 {
		t.Error("history crossed session boundaries")
	}
}

func TestEditingInterruptClearsLineAndKeepsSessionUsable(t *testing.T) {
	state := newTestState(t, "/")
	editor := &fakeEditor{steps: []editorStep{{line: "private-interrupted-line", err: shell.ErrInterrupt}, {line: "pwd"}}}
	var calls int
	execute := func(context.Context, []string, string, io.Reader, io.Writer, io.Writer) shell.Result {
		calls++
		return shell.Result{}
	}
	var stdout, stderr bytes.Buffer
	if code := shell.Run(context.Background(), editor, execute, &stdout, &stderr, shell.Options{Interactive: true, State: state}); code != 0 || calls != 0 {
		t.Error("editing interruption executed partial input or ended the session")
	}
	if strings.Contains(stdout.String()+stderr.String(), "private-interrupted-line") {
		t.Error("editing interruption exposed the discarded line")
	}
}

func TestEditorInvalidLineRejectsTheWholeInputAndRecoversOnlyInteractively(t *testing.T) {
	for _, interactive := range []bool{false, true} {
		state := newTestState(t, "/")
		editor := &fakeEditor{steps: []editorStep{
			{line: "rm --force /legacy/private-input-marker", err: shell.ErrInvalidLine},
			{line: "pwd"},
		}}
		var calls int
		execute := func(context.Context, []string, string, io.Reader, io.Writer, io.Writer) shell.Result {
			calls++
			return shell.Result{}
		}
		var stdout, stderr bytes.Buffer
		code := shell.Run(context.Background(), editor, execute, &stdout, &stderr, shell.Options{Interactive: interactive, State: state})
		wantCode := 1
		if interactive {
			wantCode = 0
		}
		if code != wantCode || calls != 0 || strings.Contains(stdout.String()+stderr.String(), "private-input-marker") {
			t.Error("invalid editor input executed a prefix, exposed raw input, or used the wrong recovery mode")
		}
		if interactive && !strings.Contains(stdout.String(), `"path":"/"`) {
			t.Error("interactive session did not execute the builtin after rejected input")
		}
		if !interactive && stdout.Len() != 0 {
			t.Error("batch session continued after the rejected physical line")
		}
		for _, history := range editor.histories {
			if strings.Contains(strings.Join(history, "\n"), "private-input-marker") {
				t.Error("editor invalid-line recovery retained rejected raw input in history")
			}
		}
	}
}

func TestCommandInterruptCancelsOnlyTheCurrentOperation(t *testing.T) {
	state := newTestState(t, "/")
	interrupts := make(chan os.Signal, 1)
	editor := &fakeEditor{steps: []editorStep{{line: "cat /secret/slow"}, {line: "pwd"}}}
	var canceled atomic.Bool
	execute := func(ctx context.Context, _ []string, _ string, _ io.Reader, _, _ io.Writer) shell.Result {
		interrupts <- os.Interrupt
		select {
		case <-ctx.Done():
			canceled.Store(true)
			return shell.Result{Code: 1}
		case <-time.After(2 * time.Second):
			t.Error("interrupt did not cancel the current command context")
			return shell.Result{Code: 1}
		}
	}
	var stdout, stderr bytes.Buffer
	if code := shell.Run(context.Background(), editor, execute, &stdout, &stderr, shell.Options{Interactive: true, State: state, Interrupts: interrupts}); code != 0 || !canceled.Load() {
		t.Error("command interruption canceled the whole interactive session")
	}
	if !strings.Contains(strings.Join(editor.prompts, "\n"), "[130] secretwright:/> ") || !strings.Contains(stdout.String(), `"path":"/"`) {
		t.Error("session did not expose interrupt status and execute the following builtin")
	}
}

func TestSessionRejectsInvalidStateAndHandlesIOErrorsSafely(t *testing.T) {
	for _, cwd := range []string{"relative", "/private\nmarker", "/private%marker"} {
		if _, err := shell.NewState(cwd); err == nil {
			t.Error("session accepted an invalid initial logical working directory")
		}
	}
	for _, test := range []struct {
		name   string
		editor *fakeEditor
		output io.Writer
	}{
		{name: "editor read", editor: &fakeEditor{steps: []editorStep{{err: errors.New("private-editor-marker")}}}, output: io.Discard},
		{name: "history replacement", editor: &fakeEditor{steps: []editorStep{{line: "pwd"}}, historyErr: errors.New("private-editor-marker")}, output: io.Discard},
		{name: "builtin output", editor: &fakeEditor{steps: []editorStep{{line: "pwd"}}}, output: privateErrorWriter{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stderr bytes.Buffer
			code := shell.Run(context.Background(), test.editor, noOpExecute, test.output, &stderr, shell.Options{State: newTestState(t, "/")})
			if code != 1 || strings.Contains(stderr.String(), "private-editor-marker") {
				t.Error("session IO error was not safely classified")
			}
		})
	}
}

type privateErrorWriter struct{}

func (privateErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("private-editor-marker")
}

func TestParentCancellationStopsSessionAndClosesEditor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	editor := &fakeEditor{steps: []editorStep{{before: cancel, err: context.Canceled}}}
	var stderr bytes.Buffer
	if code := shell.Run(ctx, editor, noOpExecute, io.Discard, &stderr, shell.Options{Interactive: true, State: newTestState(t, "/")}); code != 130 || editor.closeCount != 1 {
		t.Error("parent cancellation did not terminate and close the session")
	}
}
