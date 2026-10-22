package shell

import (
	"context"
	"errors"
	"io"
	"os"

	_ "github.com/chzyer/readline"
)

const MaxLineBytes = 64 * 1024

var (
	ErrInterrupt = errors.New("shell input interrupted")
	ErrLineTooLong = errors.New("shell line too long")
	ErrInvalidLine = errors.New("invalid shell command")
)

type Editor interface {
	ReadLine(context.Context, string) (string, error)
	ReplaceHistory([]string) error
	Close() error
}

type Result struct { Code int; CWD string }
type Executor func(context.Context, []string, string, io.Reader, io.Writer, io.Writer) Result
type Options struct { Interactive bool; State *State; Interrupts <-chan os.Signal }
type State struct{}
type Lister func(context.Context, string, string) ([]string, error)
func NewState(cwd string) (*State, error) { return &State{}, nil }
func (s *State) Directory() string { return "/" }
func (s *State) Status() int { return 0 }
func (s *State) History() []string { return []string{} }
func Parse(line string) ([]string,error) { return nil,ErrInvalidLine }
func SafeHistory(args []string) (string,bool) { return "",false }
func Complete(ctx context.Context,line []rune,pos int,cwd string,list Lister) ([][]rune,int) { return nil,0 }
func Run(ctx context.Context,editor Editor,execute Executor,stdout,stderr io.Writer,options Options) int { return 1 }
type pendingEditor struct{}
func (e *pendingEditor) ReadLine(context.Context,string) (string,error) { return "",io.EOF }
func (e *pendingEditor) ReplaceHistory([]string) error { return nil }
func (e *pendingEditor) Close() error { return nil }
func NewStreamEditor(input io.Reader) Editor { return &pendingEditor{} }
func NewTerminalEditor(input io.ReadCloser,stdout,stderr io.Writer,complete func([]rune,int)([][]rune,int)) (Editor,error) { return &pendingEditor{},nil }
func IsTerminal(input,output *os.File) bool { return false }
