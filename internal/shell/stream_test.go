package shell_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/shell"
)

type trackedInput struct {
	*strings.Reader
	closed bool
}

func (input *trackedInput) Close() error {
	input.closed = true
	return nil
}

func TestStreamEditorPreservesCRLFAndFinalUnterminatedCommand(t *testing.T) {
	input := &trackedInput{Reader: strings.NewReader("pwd\r\nls /secret\nversion")}
	editor := shell.NewStreamEditor(input)
	for _, want := range []string{"pwd", "ls /secret", "version"} {
		line, err := editor.ReadLine(context.Background(), "must-not-be-printed")
		if err != nil || line != want {
			t.Errorf("stream command = %q, error %v", line, err)
		}
	}
	if _, err := editor.ReadLine(context.Background(), ""); !errors.Is(err, io.EOF) {
		t.Errorf("stream end classification = %v", err)
	}
	if err := editor.Close(); err != nil || input.closed {
		t.Error("stream editor closed its borrowed input")
	}
}

func TestStreamEditorRejectsOverlongLineAsAWhole(t *testing.T) {
	editor := shell.NewStreamEditor(strings.NewReader("ls " + strings.Repeat("a", shell.MaxLineBytes) + "\n"))
	defer editor.Close()
	line, err := editor.ReadLine(context.Background(), "")
	if !errors.Is(err, shell.ErrLineTooLong) || line != "" {
		t.Error("stream editor exposed an executable truncated command")
	}
}

func TestStreamEditorHonorsCancellationBeforeReading(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	editor := shell.NewStreamEditor(strings.NewReader("pwd\n"))
	defer editor.Close()
	if _, err := editor.ReadLine(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled stream read classification = %v", err)
	}
}

func TestStreamSessionStopsBeforeExecutingAnOversizedPrefix(t *testing.T) {
	editor := shell.NewStreamEditor(strings.NewReader("pwd\nls " + strings.Repeat("a", shell.MaxLineBytes) + "\nrm --force /legacy/never-run\n"))
	var executed int
	execute := func(context.Context, []string, string, io.Reader, io.Writer, io.Writer) shell.Result {
		executed++
		return shell.Result{}
	}
	if code := shell.Run(context.Background(), editor, execute, io.Discard, io.Discard, shell.Options{State: newTestState(t, "/")}); code != 1 || executed != 0 {
		t.Error("batch session executed a truncated or subsequent command after an oversized line")
	}
}
