package shell_test

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/shell"
)

type blockedBorrowedInput struct {
	started  chan struct{}
	release  chan struct{}
	returned chan struct{}
	closed   atomic.Bool
}

func (input *blockedBorrowedInput) Read([]byte) (int, error) {
	close(input.started)
	<-input.release
	close(input.returned)
	return 0, io.EOF
}

func (input *blockedBorrowedInput) Close() error {
	input.closed.Store(true)
	return nil
}

func TestParentCancellationStopsAStreamBlockedOnBorrowedInput(t *testing.T) {
	input := &blockedBorrowedInput{started: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(input.release) }) }
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := newTestState(t, "/secret")
	var executed atomic.Int32
	execute := func(context.Context, []string, string, io.Reader, io.Writer, io.Writer) shell.Result {
		executed.Add(1)
		return shell.Result{}
	}
	finished := make(chan int, 1)
	go func() {
		finished <- shell.Run(ctx, shell.NewStreamEditor(input), execute, io.Discard, io.Discard, shell.Options{State: state})
	}()
	select {
	case <-input.started:
	case <-time.After(2 * time.Second):
		t.Fatal("stream session did not reach its borrowed blocking read")
	}
	cancel()
	select {
	case code := <-finished:
		if code != 130 || state.Status() != 130 || executed.Load() != 0 {
			t.Error("canceling a blocked stream lost cancellation status or dispatched a command")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parent cancellation waited for the borrowed reader to become readable")
	}
	if input.closed.Load() {
		t.Error("stream cancellation closed input owned by the caller")
	}
	release()
	select {
	case <-input.returned:
	case <-time.After(2 * time.Second):
		t.Error("the borrowed read did not finish after its owner released it")
	}
}
