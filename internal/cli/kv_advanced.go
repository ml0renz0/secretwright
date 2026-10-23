package cli

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

const advancedOptionsUsage = `Options must precede paths. Common KV options:
  --address URL, --namespace NAME, --timeout DURATION, --token-file FILE,
  --cwd PATH, paired --mount PATH --kv-version 1|2, --concurrency 1..16.
Default concurrency is 4. The timeout bounds the whole operation.
Input files contain JSON and may never be '-'. Run secretwright help for details.
`

var advancedUsage = map[string]string{
	"tree": `Usage: secretwright tree [options] [PATH]

List directory descendants as sorted JSON metadata, without reading values.
PATH defaults to '.'. Any denied subtree or traversal limit fails the operation.
`,
	"find": `Usage: secretwright find --file MATCH.json [options] [PATH]

Return paths whose current values equal the complete nonempty JSON match object.
Comparison preserves numbers and ignores object member order. PATH defaults to '.'.
`,
	"replace": `Usage: secretwright replace --file RULE.json [--force] [--dry-run] [options] [PATH]

Replace whole matching objects. RULE has only match and replacement objects.
PATH defaults to '.'. Unchanged values create no revision. KV v2 uses captured
revisions as CAS; KV v1 requires --force. --dry-run performs planning only.
`,
	"cptree": `Usage: secretwright cptree [--force] [--dry-run] [options] SOURCE DEST

Copy current snapshots under SOURCE into DEST, preserving relative paths.
Overlapping directories are rejected. KV v2 creates only; KV v1 requires --force.
The copy is not atomic. Reports contain metadata, never secret values.
`,
	"rmtree": `Usage: secretwright rmtree [--force] [--dry-run] [options] PATH

Delete current snapshots under an explicit subtree. Mount roots are rejected.
KV v2 deletes only captured revisions; KV v1 requires --force. Metadata and
historical revisions are retained. This operation is not atomic.
`,
	"backup": `Usage: secretwright backup --file OUTPUT.json [options] PATH

Save current snapshots to a private plaintext JSON archive. The output file must
not already exist. A complete archive is published atomically with mode 0600.
Only root and entry count are printed; history, ACLs and mounts are not exported.
`,
	"restore": `Usage: secretwright restore --file INPUT.json [--force] [--dry-run] [options] DEST

Validate a complete archive before authentication or requests, then restore its
relative paths under DEST. KV v2 creates only; KV v1 requires --force. Mounts,
ACLs and history are never restored. The operation is not atomic.
`,
}

type advancedCommandOptions struct {
	network     networkOptions
	bulk        vault.BulkOptions
	target      string
	destination string
	file        string
}

func parseAdvancedCommandOptions(command string, args []string) (advancedCommandOptions, bool, error) {
	var options advancedCommandOptions
	var address, namespace string
	var timeout time.Duration
	flags := flag.NewFlagSet("secretwright "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&address, "address", "", "Vault URL")
	flags.StringVar(&namespace, "namespace", "", "Vault namespace")
	flags.DurationVar(&timeout, "timeout", 0, "whole operation timeout")
	flags.StringVar(&options.network.tokenFile, "token-file", "", "token file")
	flags.StringVar(&options.bulk.CWD, "cwd", "/", "logical working directory")
	flags.StringVar(&options.bulk.Mount, "mount", "", "explicit KV mount")
	flags.IntVar(&options.bulk.Version, "kv-version", 0, "explicit KV version")
	flags.IntVar(&options.bulk.Concurrency, "concurrency", vault.DefaultConcurrency, "maximum workers")
	switch command {
	case "find", "replace", "backup", "restore":
		flags.StringVar(&options.file, "file", "", "JSON file")
	}
	switch command {
	case "replace", "cptree", "rmtree", "restore":
		flags.BoolVar(&options.bulk.Force, "force", false, "allow KV v1 mutations")
		flags.BoolVar(&options.bulk.DryRun, "dry-run", false, "plan without mutation")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return options, true, nil
		}
		return options, false, errInvalidOptions
	}
	var invalid, mountSet, versionSet bool
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
		case "mount":
			mountSet = true
		case "kv-version":
			versionSet = true
		}
	})
	if invalid || options.bulk.Concurrency < 1 || options.bulk.Concurrency > vault.MaxConcurrency ||
		mountSet != versionSet || (mountSet && (options.bulk.Mount == "" || (options.bulk.Version != 1 && options.bulk.Version != 2))) {
		return options, false, errInvalidOptions
	}
	if mountSet {
		mount := strings.Trim(options.bulk.Mount, "/")
		if _, err := vault.ResolvePath("/", mount); err != nil || mount == "" {
			return options, false, errInvalidOptions
		}
		for _, segment := range strings.Split(mount, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return options, false, errInvalidOptions
			}
		}
	}
	switch command {
	case "find", "replace", "backup", "restore":
		if options.file == "" || options.file == "-" {
			return options, false, errInvalidOptions
		}
	}
	paths := flags.Args()
	switch command {
	case "tree", "find", "replace":
		if len(paths) > 1 {
			return options, false, errInvalidOptions
		}
		options.target = "."
		if len(paths) == 1 {
			options.target = paths[0]
		}
	case "cptree":
		if len(paths) != 2 {
			return options, false, errInvalidOptions
		}
		options.target, options.destination = paths[0], paths[1]
	default:
		if len(paths) != 1 {
			return options, false, errInvalidOptions
		}
		options.target = paths[0]
	}
	if !strings.HasPrefix(options.bulk.CWD, "/") {
		return options, false, errInvalidOptions
	}
	if _, err := vault.ResolvePath(options.bulk.CWD, options.target); err != nil {
		return options, false, errInvalidOptions
	}
	if options.destination != "" {
		if _, err := vault.ResolvePath(options.bulk.CWD, options.destination); err != nil {
			return options, false, errInvalidOptions
		}
	}
	return options, false, nil
}

func kvAdvancedCommand(ctx context.Context, command string, args []string, stdout, stderr io.Writer) int {
	options, help, err := parseAdvancedCommandOptions(command, args)
	if help {
		return writeUsage(stdout, stderr, advancedUsage[command]+"\n"+advancedOptionsUsage)
	}
	if err != nil {
		return commandError(stderr, err)
	}
	// Input validation precedes credentials and client construction. Input files
	// never share stdin with command streams or the interactive line editor.
	var match, replacement map[string]any
	var archive vault.Archive
	switch command {
	case "find":
		match, err = readSecretInput(nil, options.file)
	case "replace", "restore":
		var file *os.File
		file, err = os.Open(options.file)
		if err != nil {
			err = errReadInput
			break
		}
		if command == "replace" {
			match, replacement, err = vault.DecodeReplaceRule(file)
		} else {
			archive, err = vault.DecodeArchive(file)
		}
		_ = file.Close()
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
	case "tree":
		result, err := client.Walk(ctx, token, options.target, options.bulk.RecursiveOptions)
		if err != nil {
			return kvError(stderr, err)
		}
		return writeJSON(stdout, stderr, result)
	case "find":
		result, err := client.Find(ctx, token, options.target, match, options.bulk.RecursiveOptions)
		if err != nil {
			return kvError(stderr, err)
		}
		if result == nil {
			result = []string{}
		}
		return writeJSON(stdout, stderr, result)
	case "backup":
		result, err := client.Backup(ctx, token, options.target, options.bulk.RecursiveOptions)
		if err != nil {
			return kvError(stderr, err)
		}
		if err := writeBackupArchive(options.file, result); err != nil {
			return commandError(stderr, err)
		}
		return writeJSON(stdout, stderr, struct {
			Root    string `json:"root"`
			Entries int    `json:"entries"`
		}{Root: result.Root, Entries: len(result.Entries)})
	}
	var result vault.BulkResult
	switch command {
	case "replace":
		result, err = client.Replace(ctx, token, options.target, match, replacement, options.bulk)
	case "cptree":
		result, err = client.CopyTree(ctx, token, options.target, options.destination, options.bulk)
	case "rmtree":
		result, err = client.RemoveTree(ctx, token, options.target, options.bulk)
	case "restore":
		result, err = client.Restore(ctx, token, options.target, archive, options.bulk)
	default:
		return commandError(stderr, errInvalidOptions)
	}
	if err != nil {
		if len(result.Items) != 0 {
			if code := writeJSON(stdout, stderr, result); code != 0 {
				return code
			}
		}
		return kvError(stderr, err)
	}
	return writeJSON(stdout, stderr, result)
}
