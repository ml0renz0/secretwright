package shell

import (
	"bufio"
	"context"
	"errors"
	"io"
	"sync"
)

type streamResult struct {
	line string
	err  error
}

type streamEditor struct {
	reader   *bufio.Reader
	requests chan struct{}
	results  chan streamResult
	done     chan struct{}
	start    sync.Once
	close    sync.Once
}

// NewStreamEditor reads only when the session requests another command. Close
// unblocks ReadLine without closing the caller's reader. A generic reader that
// is blocked inside Read cannot itself be interrupted without its owner's help;
// at most one worker remains until that borrowed read returns.
func NewStreamEditor(input io.Reader) Editor {
	if input == nil {
		input = &emptyReader{}
	}
	return &streamEditor{
		reader:   bufio.NewReader(input),
		requests: make(chan struct{}),
		results:  make(chan streamResult),
		done:     make(chan struct{}),
	}
}

func (s *streamEditor) ReadLine(ctx context.Context, _ string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.start.Do(func() { go s.readLoop() })
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-s.done:
		return "", io.EOF
	case s.requests <- struct{}{}:
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-s.done:
		return "", io.EOF
	case result := <-s.results:
		return result.line, result.err
	}
}

func (s *streamEditor) ReplaceHistory([]string) error {
	return nil
}

func (s *streamEditor) Close() error {
	s.close.Do(func() { close(s.done) })
	return nil
}

func (s *streamEditor) readLoop() {
	for {
		select {
		case <-s.done:
			return
		case <-s.requests:
		}
		line, err := s.readBoundedLine()
		select {
		case <-s.done:
			return
		case s.results <- streamResult{line: line, err: err}:
		}
	}
}

func (s *streamEditor) readBoundedLine() (string, error) {
	var line []byte
	tooLong := false
	for {
		fragment, err := s.reader.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(fragment) > MaxLineBytes+2 {
				tooLong = true
				line = nil
			} else {
				line = append(line, fragment...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return "", errors.New("could not read shell input")
		}
		if tooLong {
			return "", ErrLineTooLong
		}
		if len(line) != 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}
		if len(line) != 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) > MaxLineBytes {
			return "", ErrLineTooLong
		}
		if len(line) == 0 && errors.Is(err, io.EOF) {
			return "", io.EOF
		}
		return string(line), nil
	}
}

type emptyReader struct{}

func (*emptyReader) Read([]byte) (int, error) {
	return 0, io.EOF
}
