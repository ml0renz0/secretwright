package cli

import (
	"context"
	"errors"
	"flag"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

const putUsage = `Usage: secretwright put [options] [--file FILE] [--cas N] PATH

Replace all secret values with one nonempty JSON object, at most 1 MiB.
Read JSON from stdin by default; --file - also reads stdin. Secret values are
never accepted as arguments. KV v2 creates by default (CAS 0); --cas N updates
only a matching revision. KV v1 replaces directly and does not accept --cas.
Options must precede PATH. Run secretwright help for common KV options.
`

const removeUsage = `Usage: secretwright rm [options] [--versions CSV] [--force] PATH

Delete one secret, never a directory or metadata. KV v2 soft-deletes the latest
revision, or the positive revision IDs supplied by --versions. KV v1 permanently
deletes the key and requires --force; --versions is not supported for KV v1.
Options must precede PATH. Run secretwright help for common KV options.
`

const copyUsage = `Usage: secretwright cp [options] [--cas N] [--force] SOURCE DEST

Copy current secret values. KV v2 destinations create by default (CAS 0);
--cas N updates only a matching revision. KV v1 destinations require --force
and reject --cas. Cross-mount operations use automatic mount discovery.
Options must precede paths. Run secretwright help for common KV options.
`

const moveUsage = `Usage: secretwright mv [options] [--cas N] [--force] SOURCE DEST

Copy current values, then delete the source revision. This is not atomic.
KV v2 destinations create by default (CAS 0); --cas N updates a matching revision.
KV v1 source deletion or destination replacement requires --force.
Exit 5 means the destination was written but source deletion was not confirmed;
verify both paths before retrying. The destination is never rolled back.
Options must precede paths. Run secretwright help for common KV options.
`

const versionsUsage = `Usage: secretwright versions [options] PATH

Print KV v2 version metadata as JSON, without secret values or custom metadata.
Options must precede PATH. Run secretwright help for common KV options.
`

const undeleteUsage = `Usage: secretwright undelete [options] --versions CSV PATH

Restore the selected KV v2 revisions. CSV contains positive revision IDs.
Options must precede PATH. Run secretwright help for common KV options.
`

const destroyUsage = `Usage: secretwright destroy [options] --versions CSV --force PATH

Permanently destroy selected KV v2 revisions, retaining their metadata.
CSV contains positive revision IDs. --force is required.
Options must precede PATH. Run secretwright help for common KV options.
`

const rollbackUsage = `Usage: secretwright rollback [options] PATH VERSION

Restore a positive KV v2 revision as a new revision, using the current revision
as CAS. Existing history is retained. Destroyed revisions cannot be restored.
Options must precede paths. Run secretwright help for common KV options.
`

type kvWriteCommandOptions struct {
	network     networkOptions
	write       vault.WriteOptions
	target      string
	destination string
	file        string
	versions    []int
	version     int
}

func parseKVWriteCommandOptions(command string, args []string) (kvWriteCommandOptions, bool, error) {
	var options kvWriteCommandOptions
	var address, namespace, revisions string
	var timeout time.Duration
	var cas int
	flags := flag.NewFlagSet("secretwright", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&address, "address", "", "Vault URL")
	flags.StringVar(&namespace, "namespace", "", "Vault namespace")
	flags.DurationVar(&timeout, "timeout", 0, "request timeout")
	flags.StringVar(&options.network.tokenFile, "token-file", "", "token file")
	flags.StringVar(&options.write.CWD, "cwd", "/", "logical working directory")
	flags.StringVar(&options.write.Mount, "mount", "", "explicit KV mount")
	flags.IntVar(&options.write.Version, "kv-version", 0, "explicit KV version")
	if command == "put" {
		flags.StringVar(&options.file, "file", "", "JSON input file, or - for stdin")
	}
	if command == "put" || command == "cp" || command == "mv" {
		flags.IntVar(&cas, "cas", 0, "required current revision")
	}
	if command == "rm" || command == "undelete" || command == "destroy" {
		flags.StringVar(&revisions, "versions", "", "positive revision IDs")
	}
	if command == "rm" || command == "destroy" || command == "cp" || command == "mv" {
		flags.BoolVar(&options.write.Force, "force", false, "allow permanent operations")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return options, true, nil
		}
		return options, false, errInvalidOptions
	}
	var invalid, mountSet, versionSet, revisionsSet bool
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
		case "cas":
			options.write.CAS = &cas
			invalid = invalid || cas < 0
		case "file":
			invalid = invalid || options.file == ""
		case "versions":
			revisionsSet = true
		}
	})
	if invalid || mountSet != versionSet || (mountSet && (options.write.Mount == "" || (options.write.Version != 1 && options.write.Version != 2))) {
		return options, false, errInvalidOptions
	}
	if revisionsSet {
		var err error
		options.versions, err = parseVersions(revisions)
		if err != nil {
			return options, false, errInvalidOptions
		}
	}
	if (command == "undelete" || command == "destroy") && !revisionsSet {
		return options, false, errInvalidOptions
	}
	if command == "destroy" && !options.write.Force {
		return options, false, errInvalidOptions
	}
	paths := flags.Args()
	if command == "cp" || command == "mv" || command == "rollback" {
		if len(paths) != 2 {
			return options, false, errInvalidOptions
		}
		options.destination = paths[1]
	} else if len(paths) != 1 {
		return options, false, errInvalidOptions
	}
	options.target = paths[0]
	if command == "rollback" {
		var err error
		options.version, err = parsePositiveVersion(paths[1])
		if err != nil {
			return options, false, errInvalidOptions
		}
	}
	return options, false, nil
}

func parsePositiveVersion(value string) (int, error) {
	if value == "" {
		return 0, errInvalidOptions
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, errInvalidOptions
		}
	}
	version, err := strconv.Atoi(value)
	if err != nil || version <= 0 {
		return 0, errInvalidOptions
	}
	return version, nil
}

func parseVersions(value string) ([]int, error) {
	seen := make(map[int]bool)
	for _, item := range strings.Split(value, ",") {
		version, err := parsePositiveVersion(item)
		if err != nil {
			return nil, errInvalidOptions
		}
		seen[version] = true
	}
	versions := make([]int, 0, len(seen))
	for version := range seen {
		versions = append(versions, version)
	}
	sort.Ints(versions)
	return versions, nil
}

func kvWriteCommand(ctx context.Context, command string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	options, help, err := parseKVWriteCommandOptions(command, args)
	if help {
		text := map[string]string{
			"put":      putUsage,
			"rm":       removeUsage,
			"cp":       copyUsage,
			"mv":       moveUsage,
			"versions": versionsUsage,
			"undelete": undeleteUsage,
			"destroy":  destroyUsage,
			"rollback": rollbackUsage,
		}[command]
		return writeUsage(stdout, stderr, text)
	}
	if err != nil {
		return commandError(stderr, err)
	}
	token, err := vault.LoadToken(options.network.tokenFile)
	if err != nil {
		return kvError(stderr, err)
	}
	var data map[string]any
	if command == "put" {
		data, err = readSecretInput(stdin, options.file)
		if err != nil {
			return commandError(stderr, err)
		}
	}
	client, err := vault.New(options.network.vault)
	if err != nil {
		return kvError(stderr, err)
	}
	var result any
	switch command {
	case "put":
		result, err = client.Put(ctx, token, options.target, data, options.write)
	case "rm":
		result, err = client.Remove(ctx, token, options.target, options.versions, options.write)
	case "cp":
		result, err = client.Copy(ctx, token, options.target, options.destination, options.write)
	case "mv":
		result, err = client.Move(ctx, token, options.target, options.destination, options.write)
	case "versions":
		result, err = client.Versions(ctx, token, options.target, options.write.KVOptions)
	case "undelete":
		result, err = client.Undelete(ctx, token, options.target, options.versions, options.write.KVOptions)
	case "destroy":
		result, err = client.Destroy(ctx, token, options.target, options.versions, options.write)
	case "rollback":
		result, err = client.Rollback(ctx, token, options.target, options.version, options.write.KVOptions)
	default:
		return commandError(stderr, errInvalidOptions)
	}
	if err != nil {
		return kvError(stderr, err)
	}
	return writeJSON(stdout, stderr, result)
}
