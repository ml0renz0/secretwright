package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/ml0renz0/secretwright/internal/shell"
	"github.com/ml0renz0/secretwright/internal/vault"
)

const shellUsage = `Usage: secretwright shell [options]

Run a Vault command session. A terminal enables editing, Tab completion and
Ctrl+R search over safe in-memory history. Piped input runs without prompts
and stops at the first error. --script FILE reads commands from a file.

Options: --address URL, --namespace NAME, --timeout DURATION, --token-file FILE,
         --cwd PATH, --no-prompt, --script FILE.
Aliases: secretwright --no-prompt; secretwright --script FILE.

pwd prints the session directory; cd changes it after successful validation.
history prints approved in-memory commands; exit or quit ends the session.
Ctrl+C cancels the current line or operation; Ctrl+D exits at an empty prompt.
Connection options and --cwd belong at session startup. put requires --file FILE
inside a session; use the one-shot put command to read JSON from stdin.
Advanced operations use the same fixed connection; JSON files never consume
commands from stdin. There is no command expansion, external shell or history file.
Access commands use the fixed connection without a KV cwd. AppRole login does
not send the operator token or replace it. Credential exports require --out FILE;
all access commands stay out of history and never print issued credentials.
Template commands remain offline, ignore the session's KV cwd and credentials,
and stay out of history. Rendered configuration is reviewed with blueprint.
`

type shellOptions struct {
	network  networkOptions
	cwd      string
	script   string
	noPrompt bool
}

func parseShellOptions(args []string) (shellOptions, bool, error) {
	var options shellOptions
	var address, namespace string
	var timeout time.Duration
	flags := flag.NewFlagSet("secretwright shell", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&address, "address", "", "Vault URL")
	flags.StringVar(&namespace, "namespace", "", "Vault namespace")
	flags.DurationVar(&timeout, "timeout", 0, "request timeout")
	flags.StringVar(&options.network.tokenFile, "token-file", "", "token file")
	flags.StringVar(&options.cwd, "cwd", "/", "initial directory")
	flags.StringVar(&options.script, "script", "", "command file")
	flags.BoolVar(&options.noPrompt, "no-prompt", false, "disable prompts")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return options, true, nil
		}
		return options, false, errInvalidOptions
	}
	invalid := flags.NArg() != 0
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "address":
			options.network.vault.Address = &address
		case "namespace":
			options.network.vault.Namespace = &namespace
		case "timeout":
			options.network.vault.Timeout = &timeout
		case "token-file":
			invalid = invalid || options.network.tokenFile == ""
		case "script":
			invalid = invalid || options.script == "" || options.script == "-"
		}
	})
	if invalid || !strings.HasPrefix(options.cwd, "/") {
		return options, false, errInvalidOptions
	}
	canonical, err := vault.ResolvePath(options.cwd, ".")
	if err != nil {
		return options, false, errInvalidOptions
	}
	options.cwd = canonical
	return options, false, nil
}

func runShell(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	options, help, err := parseShellOptions(args)
	if help {
		return writeUsage(stdout, stderr, shellUsage)
	}
	if err != nil {
		return commandError(stderr, err)
	}
	input := stdin
	if options.script != "" {
		file, err := os.Open(options.script)
		if err != nil {
			return commandError(stderr, errors.New("could not open the command file"))
		}
		defer file.Close()
		input = file
	}
	state, err := shell.NewState(options.cwd)
	if err != nil {
		return commandError(stderr, errors.New("invalid session directory"))
	}
	inputFile, inputTTY := input.(*os.File)
	outputFile, outputTTY := stderr.(*os.File)
	interactive := options.script == "" && !options.noPrompt && inputTTY && outputTTY && shell.IsTerminal(inputFile, outputFile)
	var editor shell.Editor
	if interactive {
		complete := func(line []rune, pos int) ([][]rune, int) {
			return shell.Complete(ctx, line, pos, state.Directory(), options.list)
		}
		editor, err = shell.NewTerminalEditor(inputFile, stderr, stderr, complete)
		if err != nil {
			return commandError(stderr, errors.New("could not initialize the terminal editor"))
		}
	} else {
		editor = shell.NewStreamEditor(input)
	}
	var interrupts <-chan os.Signal
	if interactive {
		channel := make(chan os.Signal, 1)
		signal.Notify(channel, os.Interrupt)
		defer signal.Stop(channel)
		interrupts = channel
	} else {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt)
		defer stop()
	}
	execute := func(commandContext context.Context, words []string, cwd string, commandInput io.Reader, output, diagnostics io.Writer) shell.Result {
		return options.execute(commandContext, words, cwd, commandInput, output, diagnostics, version)
	}
	return shell.Run(ctx, editor, execute, stdout, stderr, shell.Options{Interactive: interactive, State: state, Interrupts: interrupts})
}

func (options shellOptions) list(ctx context.Context, target, cwd string) ([]string, error) {
	token, err := vault.LoadToken(options.network.tokenFile)
	if err != nil {
		return nil, err
	}
	client, err := vault.New(options.network.vault)
	if err != nil {
		return nil, err
	}
	return client.List(ctx, token, target, vault.KVOptions{CWD: cwd})
}

// Session options are injected as argv elements, never reconstructed shell text.
// A per-line connection override would invalidate cwd and completion's scope.
func (options shellOptions) execute(ctx context.Context, words []string, cwd string, input io.Reader, stdout, stderr io.Writer, version string) shell.Result {
	if len(words) == 0 {
		return shell.Result{}
	}
	if words[0] == "shell" || words[0] == "--script" || words[0] == "--no-prompt" || shellOverrides(words) {
		return shell.Result{Code: commandError(stderr, errors.New("connection and session options must be supplied at shell startup"))}
	}
	if words[0] == "put" {
		parsed, help, err := parseKVWriteCommandOptions("put", words[1:])
		if err != nil {
			return shell.Result{Code: commandError(stderr, err)}
		}
		if !help && (parsed.file == "" || parsed.file == "-") {
			return shell.Result{Code: commandError(stderr, errors.New("shell put requires --file FILE; stdin is reserved for commands"))}
		}
	}
	args := options.commandArgs(words, cwd)
	if words[0] != "cd" {
		return shell.Result{Code: RunWithInput(ctx, args, input, stdout, stderr, version)}
	}
	if _, help, _ := parseKVCommandOptions("cd", words[1:]); help {
		return shell.Result{Code: RunWithInput(ctx, args, input, stdout, stderr, version)}
	}
	var captured bytes.Buffer
	code := RunWithInput(ctx, args, input, &captured, stderr, version)
	if code != 0 {
		return shell.Result{Code: code}
	}
	var selected struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(captured.Bytes(), &selected); err != nil || selected.Path == "" {
		return shell.Result{Code: commandError(stderr, errors.New("could not interpret the selected directory"))}
	}
	if written, err := stdout.Write(captured.Bytes()); err != nil || written != captured.Len() {
		return shell.Result{Code: commandError(stderr, errors.New("could not write output"))}
	}
	return shell.Result{CWD: selected.Path}
}

func (options shellOptions) commandArgs(words []string, cwd string) []string {
	if words[0] == "template" {
		return append([]string(nil), words...)
	}
	position := 1
	if words[0] == "blueprint" {
		action, depth := blueprintCommandPrefix(words)
		if depth == 0 || action != "plan" && action != "apply" {
			return append([]string(nil), words...)
		}
		position = depth
	}
	if words[0] == "policy" || words[0] == "approle" || words[0] == "token" || words[0] == "identity" {
		_, _, position = accessCommandPrefix(words)
		if position == 0 {
			return append([]string(nil), words...)
		}
	}
	if words[0] == "auth" && (len(words) < 2 || words[1] != "check") {
		return append([]string(nil), words...)
	}
	if words[0] == "auth" && len(words) > 1 && words[1] == "check" {
		position = 2
	}
	kv := false
	switch words[0] {
	case "mounts", "ls", "cat", "cd", "put", "rm", "cp", "mv", "versions", "undelete", "destroy", "rollback",
		"tree", "find", "replace", "cptree", "rmtree", "backup", "restore":
		kv = true
	case "status", "auth", "policy", "approle", "token", "identity", "blueprint":
	default:
		return append([]string(nil), words...)
	}
	args := append([]string(nil), words[:position]...)
	if value := options.network.vault.Address; value != nil {
		args = append(args, "--address", *value)
	}
	if value := options.network.vault.Namespace; value != nil {
		args = append(args, "--namespace", *value)
	}
	if value := options.network.vault.Timeout; value != nil {
		args = append(args, "--timeout", value.String())
	}
	anonymous := words[0] == "approle" && len(words) > 1 && words[1] == "login"
	if words[0] != "status" && !anonymous && options.network.tokenFile != "" {
		args = append(args, "--token-file", options.network.tokenFile)
	}
	if kv && words[0] != "mounts" {
		args = append(args, "--cwd", cwd)
	}
	return append(args, words[position:]...)
}

func shellOverrides(words []string) bool {
	start := 1
	if _, _, depth := accessCommandPrefix(words); depth != 0 {
		start = depth
	} else if _, depth := blueprintCommandPrefix(words); depth != 0 {
		start = depth
	} else if _, depth := templateCommandPrefix(words); depth != 0 {
		start = depth
	} else if words[0] == "auth" && len(words) > 1 && words[1] == "check" {
		start = 2
	}
	for i := start; i < len(words); i++ {
		word := words[i]
		if word == "--" || !strings.HasPrefix(word, "-") || word == "-" {
			break
		}
		name, _, equals := strings.Cut(strings.TrimLeft(word, "-"), "=")
		switch name {
		case "address", "namespace", "timeout", "token-file", "cwd":
			return true
		case "force", "dry-run", "h", "help":
			continue
		}
		if !equals {
			i++
		}
	}
	return false
}

func shellInvocation(args []string) bool {
	return len(args) > 0 && (args[0] == "shell" || args[0] == "--script" || args[0] == "--no-prompt")
}

func defaultShell(stderr io.Writer) bool {
	file, ok := stderr.(*os.File)
	return ok && shell.IsTerminal(os.Stdin, file)
}

// Keep signal registration out of RunWithInput so tests and embedding callers
// retain control of their contexts. A shell routes SIGINT per command instead.
func runWithInterrupt(ctx context.Context, args []string, stdout, stderr io.Writer, version string) int {
	if len(args) == 0 && defaultShell(stderr) {
		args = []string{"shell"}
	}
	if shellInvocation(args) {
		return RunWithInput(ctx, args, os.Stdin, stdout, stderr, version)
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	return RunWithInput(ctx, args, os.Stdin, stdout, stderr, version)
}
