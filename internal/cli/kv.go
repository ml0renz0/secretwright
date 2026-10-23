package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

const mountsUsage = `Usage: secretwright mounts [--address URL] [--namespace NAME] [--timeout DURATION] [--token-file PATH]

List visible KV v1/v2 mounts as JSON. Requires a token.
Run secretwright help for configuration variables and exit codes.
`

const listUsage = `Usage: secretwright ls [options] [PATH]

List immediate children of a logical Vault directory as JSON. PATH defaults to '.'.
Options must precede PATH; use -- to end options.
Options: --address URL, --namespace NAME, --timeout DURATION, --token-file PATH,
         --cwd PATH, and the paired --mount PATH --kv-version 1|2.
Run secretwright help for configuration variables and exit codes.
`

const readUsage = `Usage: secretwright cat [options] [--version N] PATH

Print the requested secret values to standard output as JSON. Reads the latest
value from KV v1 or KV v2; --version N reads a positive KV v2 revision.
Options must precede PATH; use -- to end options.
Options: --address URL, --namespace NAME, --timeout DURATION, --token-file PATH,
         --cwd PATH, and the paired --mount PATH --kv-version 1|2.
Run secretwright help for configuration variables and exit codes.
`

const changeDirUsage = `Usage: secretwright cd [options] [PATH]

Validate a logical directory and print its canonical path as JSON. PATH defaults
to '/'. The directory is not retained between invocations; use --cwd explicitly.
Options must precede PATH; use -- to end options.
Options: --address URL, --namespace NAME, --timeout DURATION, --token-file PATH,
         --cwd PATH, and the paired --mount PATH --kv-version 1|2.
Run secretwright help for configuration variables and exit codes.
`

type kvCommandOptions struct {
	network networkOptions
	kv      vault.KVOptions
	target  string
	version int
}

func parseKVCommandOptions(command string, args []string) (kvCommandOptions, bool, error) {
	var options kvCommandOptions
	var address, namespace string
	var timeout time.Duration
	flags := flag.NewFlagSet("secretwright", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&address, "address", "", "Vault URL")
	flags.StringVar(&namespace, "namespace", "", "Vault namespace")
	flags.DurationVar(&timeout, "timeout", 0, "request timeout")
	flags.StringVar(&options.network.tokenFile, "token-file", "", "token file")
	if command != "mounts" {
		flags.StringVar(&options.kv.CWD, "cwd", "/", "logical working directory")
		flags.StringVar(&options.kv.Mount, "mount", "", "explicit KV mount")
		flags.IntVar(&options.kv.Version, "kv-version", 0, "explicit KV version")
	}
	if command == "cat" {
		flags.IntVar(&options.version, "version", 0, "historical KV v2 revision")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return options, true, nil
		}
		return options, false, errInvalidOptions
	}
	var invalidTokenFile, mountSet, versionSet, invalidRevision bool
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "address":
			options.network.vault.Address = &address
		case "namespace":
			options.network.vault.Namespace = &namespace
		case "timeout":
			options.network.vault.Timeout = &timeout
		case "token-file":
			invalidTokenFile = options.network.tokenFile == ""
		case "mount":
			mountSet = true
		case "kv-version":
			versionSet = true
		case "version":
			invalidRevision = options.version <= 0
		}
	})
	if invalidTokenFile || invalidRevision || mountSet != versionSet || (mountSet && (options.kv.Mount == "" || (options.kv.Version != 1 && options.kv.Version != 2))) {
		return options, false, errInvalidOptions
	}
	paths := flags.Args()
	if command == "mounts" {
		if len(paths) != 0 {
			return options, false, errInvalidOptions
		}
		return options, false, nil
	}
	if len(paths) > 1 || (command == "cat" && len(paths) != 1) {
		return options, false, errInvalidOptions
	}
	if len(paths) == 1 {
		options.target = paths[0]
	} else if command == "cd" {
		options.target = "/"
	} else {
		options.target = "."
	}
	return options, false, nil
}

func kvCommand(ctx context.Context, command string, args []string, stdout, stderr io.Writer) int {
	options, help, err := parseKVCommandOptions(command, args)
	if help {
		text := map[string]string{"mounts": mountsUsage, "ls": listUsage, "cat": readUsage, "cd": changeDirUsage}[command]
		return writeUsage(stdout, stderr, text)
	}
	if err != nil {
		return commandError(stderr, err)
	}
	token, err := vault.LoadToken(options.network.tokenFile)
	if err != nil {
		return kvError(stderr, err)
	}
	client, err := vault.New(options.network.vault)
	if err != nil {
		return kvError(stderr, err)
	}
	switch command {
	case "mounts":
		mounts, err := client.Mounts(ctx, token)
		if err != nil {
			return kvError(stderr, err)
		}
		if mounts == nil {
			mounts = []vault.Mount{}
		}
		return writeJSON(stdout, stderr, mounts)
	case "ls":
		children, err := client.List(ctx, token, options.target, options.kv)
		if err != nil {
			return kvError(stderr, err)
		}
		if children == nil {
			children = []string{}
		}
		return writeJSON(stdout, stderr, children)
	case "cat":
		var data map[string]any
		var err error
		if options.version > 0 {
			data, err = client.ReadVersion(ctx, token, options.target, options.version, options.kv)
		} else {
			data, err = client.Read(ctx, token, options.target, options.kv)
		}
		if err != nil {
			return kvError(stderr, err)
		}
		return writeJSON(stdout, stderr, data)
	case "cd":
		path, err := client.ChangeDir(ctx, token, options.target, options.kv)
		if err != nil {
			return kvError(stderr, err)
		}
		return writeJSON(stdout, stderr, struct {
			Path string `json:"path"`
		}{Path: path})
	}
	return commandError(stderr, errInvalidOptions)
}

func kvError(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "secretwright:", err)
	if errors.Is(err, vault.ErrPartial) || errors.Is(err, vault.ErrBulkPartial) {
		return 5
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	if errors.Is(err, vault.ErrConflict) {
		return 4
	}
	if errors.Is(err, vault.ErrUnauthenticated) || errors.Is(err, vault.ErrPermissionDenied) {
		return 2
	}
	if errors.Is(err, vault.ErrNotFound) {
		return 3
	}
	return 1
}
