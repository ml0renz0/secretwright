package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ml0renz0/secretwright/internal/fileformat"
	"github.com/ml0renz0/secretwright/internal/keytab"
	"github.com/ml0renz0/secretwright/internal/vault"
)

const keytabUsage = `Usage: secretwright keytab ACTION [options]

  schema                         Export the policy JSON Schema offline
  example [--format yaml|json]    Print an editable policy (default YAML)
  inspect --file BINARY           Inspect keytab v2 metadata offline
  validate --file BINARY [--policy POLICY]
  import --file BINARY --mount M --path /M/key [--cas N] [--policy POLICY]
  export --mount M --path /M/key --out NEW.keytab [--version N] [--policy POLICY]

Schema, example, inspect and validate run offline. Only keytab v2 is supported;
legacy native-endian v1 is rejected. Reports contain principal, KVNO, enctype
and creation metadata, never keys, encoded data or key fingerprints. Every
report declares authentication_checked:false: structural and policy validation
does not contact a KDC, authenticate an account or prove that keys are current.
An entry timestamp is creation metadata, never account or ticket expiry.

Import and export use an existing explicit KV v2 mount and canonical absolute
path. Import creates with CAS 0 by default; --cas N replaces an exact revision.
Export reads the current revision or exactly --version N, with no fallback to
older, deleted or destroyed revisions. Policy checks never filter stored bytes.

Online options: --address URL, --namespace NAME, --timeout DURATION and
--token-file FILE. The timeout covers the complete online operation. There is
no KV discovery, cwd, KV1, stdin, '-' filename, key generation or KDC mutation.

Input keytabs must be private regular files with mode 0600, without final
symlinks. Exports reserve a new private 0600 file before contacting Vault and
never overwrite an existing path. Generated policies default to YAML with
JSON optional; keytab files remain binary. All keytab commands stay out of
shell history and completion never lists private paths or principals.

Import is never automatically retried or compensated. Exit 5 means its Vault
write may have applied or confirmed metadata could not be printed; inspect
the stored revision before explicitly retrying. Export retains a successfully
saved private file if printing its metadata fails.
`

var errKeytabPartial = errors.New("keytab import outcome requires inspection before retrying")

type keytabCommandOptions struct {
	action   string
	file     string
	policy   string
	output   string
	target   string
	kv       vault.KVOptions
	cas      *int
	revision int
	format   fileformat.Format
	network  networkOptions
}

func keytabCommandPrefix(words []string) (string, int) {
	if len(words) < 2 || words[0] != "keytab" {
		return "", 0
	}
	switch words[1] {
	case "schema", "example", "inspect", "validate", "import", "export":
		return words[1], 2
	}
	return "", 0
}

func keytabOnline(action string) bool {
	return action == "import" || action == "export"
}

func keytabFilename(path string) bool {
	return path != "" && path != "-" && len(path) <= 4096 && utf8.ValidString(path) && strings.IndexFunc(path, unicode.IsControl) < 0
}

func parseKeytabCommandOptions(words []string) (keytabCommandOptions, bool, error) {
	var options keytabCommandOptions
	var depth int
	options.action, depth = keytabCommandPrefix(words)
	if depth == 0 {
		return options, false, errInvalidOptions
	}
	flags := flag.NewFlagSet("secretwright keytab", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	fileRequired := options.action == "inspect" || options.action == "validate" || options.action == "import"
	if fileRequired {
		flags.StringVar(&options.file, "file", "", "private binary keytab input")
	}
	if options.action == "validate" || keytabOnline(options.action) {
		flags.StringVar(&options.policy, "policy", "", "optional structured identity policy")
	}
	var address, namespace, encoding string
	var timeout time.Duration
	var cas int
	if keytabOnline(options.action) {
		options.kv.CWD, options.kv.Version = "/", 2
		flags.StringVar(&options.kv.Mount, "mount", "", "explicit KV v2 mount")
		flags.StringVar(&options.target, "path", "", "canonical absolute path below the mount")
		flags.StringVar(&address, "address", "", "Vault URL")
		flags.StringVar(&namespace, "namespace", "", "Vault namespace")
		flags.DurationVar(&timeout, "timeout", 0, "complete operation timeout")
		flags.StringVar(&options.network.tokenFile, "token-file", "", "operator token file")
	}
	if options.action == "import" {
		flags.IntVar(&cas, "cas", 0, "exact revision to replace; default create-only")
	}
	if options.action == "export" {
		flags.IntVar(&options.revision, "version", 0, "exact positive historical revision")
		flags.StringVar(&options.output, "out", "", "new private binary output")
	}
	if options.action == "example" {
		flags.StringVar(&encoding, "format", "", "yaml or json")
	}
	if err := flags.Parse(words[depth:]); err != nil {
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
			invalid = invalid || timeout <= 0
		case "token-file":
			invalid = invalid || !keytabFilename(options.network.tokenFile)
		case "policy":
			invalid = invalid || !keytabFilename(options.policy)
		case "cas":
			invalid = invalid || cas < 0
			options.cas = &cas
		case "version":
			invalid = invalid || options.revision <= 0
		case "format":
			invalid = invalid || encoding == ""
		}
	})
	invalid = invalid || fileRequired && !keytabFilename(options.file)
	if options.action == "export" {
		invalid = invalid || !keytabFilename(options.output)
	}
	if keytabOnline(options.action) {
		invalid = invalid || vault.ValidateKeytabTarget(options.target, options.kv) != nil
	}
	if options.action == "example" {
		var err error
		options.format, err = fileformat.Parse(encoding)
		invalid = invalid || err != nil
	}
	if invalid {
		return options, false, errInvalidOptions
	}
	return options, false, nil
}

func keytabCommand(ctx context.Context, words []string, stdout, stderr io.Writer) int {
	if len(words) == 1 || len(words) == 2 && (words[1] == "help" || words[1] == "-h" || words[1] == "--help") {
		return writeKeytabBytes(stdout, stderr, []byte(keytabUsage), false)
	}
	options, help, err := parseKeytabCommandOptions(words)
	if help {
		return writeKeytabBytes(stdout, stderr, []byte(keytabUsage), false)
	}
	if err != nil {
		return keytabCLIError(stderr, err)
	}
	switch options.action {
	case "schema":
		return writeKeytabBytes(stdout, stderr, keytab.Schema(), false)
	case "example":
		body, err := fileformat.EncodeJSON(keytab.Example(), options.format)
		if err != nil {
			return keytabCLIError(stderr, err)
		}
		return writeKeytabBytes(stdout, stderr, body, false)
	}
	if err := ctx.Err(); err != nil {
		return keytabCLIError(stderr, err)
	}
	if keytabOnline(options.action) {
		return keytabVaultCommand(ctx, options, stdout, stderr)
	}
	policy, err := optionalKeytabPolicy(options.policy)
	if err != nil {
		return keytabCLIError(stderr, err)
	}
	raw, err := readKeytabFile(options.file)
	if err != nil {
		return keytabCLIError(stderr, err)
	}
	if options.action == "inspect" {
		report, err := keytab.Inspect(bytes.NewReader(raw))
		if err != nil {
			return keytabCLIError(stderr, err)
		}
		return writeKeytabJSON(stdout, stderr, report, false)
	}
	report, err := keytab.Validate(bytes.NewReader(raw), policy)
	if err == nil || errors.Is(err, keytab.ErrValidation) {
		if code := writeKeytabJSON(stdout, stderr, report, false); code != 0 {
			return code
		}
	}
	if err != nil {
		return keytabCLIError(stderr, err)
	}
	return 0
}

func optionalKeytabPolicy(path string) (keytab.Policy, error) {
	if path == "" {
		return keytab.Policy{}, nil
	}
	return readKeytabPolicy(path)
}

type keytabTransferReport struct {
	Operation string        `json:"operation"`
	Path      string        `json:"path"`
	Version   int           `json:"version"`
	Report    keytab.Report `json:"report"`
}

func keytabVaultCommand(ctx context.Context, options keytabCommandOptions, stdout, stderr io.Writer) int {
	policy, err := optionalKeytabPolicy(options.policy)
	if err != nil {
		return keytabCLIError(stderr, err)
	}
	var raw []byte
	var inspected keytab.Report
	if options.action == "import" {
		raw, err = readKeytabFile(options.file)
		if err != nil {
			return keytabCLIError(stderr, err)
		}
		validation, err := keytab.Validate(bytes.NewReader(raw), policy)
		if err != nil {
			if errors.Is(err, keytab.ErrValidation) {
				if code := writeKeytabJSON(stdout, stderr, validation, false); code != 0 {
					return code
				}
			}
			return keytabCLIError(stderr, err)
		}
		inspected, err = keytab.Inspect(bytes.NewReader(raw))
		if err != nil {
			return keytabCLIError(stderr, err)
		}
	}
	var output *credentialOutput
	if options.action == "export" {
		output, err = reserveKeytabOutput(options.output)
		if err != nil {
			return keytabCLIError(stderr, err)
		}
		defer output.abort()
	}
	if err := ctx.Err(); err != nil {
		return keytabCLIError(stderr, err)
	}
	operator, err := vault.LoadToken(options.network.tokenFile)
	if err != nil {
		return keytabCLIError(stderr, err)
	}
	client, err := vault.New(options.network.vault)
	if err != nil {
		return keytabCLIError(stderr, err)
	}
	ctx, cancel := context.WithTimeout(ctx, client.OperationTimeout())
	defer cancel()
	if options.action == "import" {
		written, err := client.StoreKeytab(ctx, operator, options.target, raw, options.cas, options.kv)
		if err != nil {
			return keytabCLIError(stderr, err)
		}
		return writeKeytabJSON(stdout, stderr, keytabTransferReport{Operation: "import", Path: written.Path, Version: written.Version, Report: inspected}, true)
	}
	stored, err := client.ReadKeytab(ctx, operator, options.target, options.revision, options.kv)
	if err != nil {
		return keytabCLIError(stderr, err)
	}
	validation, err := keytab.Validate(bytes.NewReader(stored.Data), policy)
	if err != nil {
		if errors.Is(err, keytab.ErrValidation) {
			if code := writeKeytabJSON(stdout, stderr, validation, false); code != 0 {
				return code
			}
		}
		return keytabCLIError(stderr, err)
	}
	if err := ctx.Err(); err != nil {
		return keytabCLIError(stderr, err)
	}
	if err := commitKeytabOutput(output, stored.Data); err != nil {
		return keytabCLIError(stderr, err)
	}
	return writeKeytabJSON(stdout, stderr, keytabTransferReport{Operation: "export", Path: stored.Path, Version: stored.Version, Report: stored.Report}, false)
}

func writeKeytabJSON(stdout, stderr io.Writer, value any, mutation bool) int {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		if mutation {
			return keytabCLIError(stderr, errKeytabPartial)
		}
		return keytabCLIError(stderr, err)
	}
	return writeKeytabBytes(stdout, stderr, append(body, '\n'), mutation)
}

func writeKeytabBytes(stdout, stderr io.Writer, body []byte, mutation bool) int {
	written, err := stdout.Write(body)
	if err != nil || written != len(body) {
		if mutation {
			return keytabCLIError(stderr, errKeytabPartial)
		}
		fmt.Fprintln(stderr, "secretwright: could not write keytab output")
		return 1
	}
	return 0
}

func keytabCLIError(stderr io.Writer, err error) int {
	code, message := 1, "invalid keytab options, input, policy, file or response"
	switch {
	case errors.Is(err, errKeytabPartial), errors.Is(err, vault.ErrAccessUnconfirmed), errors.Is(err, vault.ErrAccessPartial):
		code, message = 5, "keytab import outcome requires inspection before retrying"
	case errors.Is(err, keytab.ErrValidation), errors.Is(err, errKeytabOutputConflict), errors.Is(err, vault.ErrConflict):
		code, message = 4, "keytab policy, output or revision conflict"
	case errors.Is(err, context.Canceled):
		code, message = 130, "keytab operation canceled"
	case errors.Is(err, vault.ErrPermissionDenied), errors.Is(err, vault.ErrUnauthenticated):
		code, message = 2, "keytab authentication or permission denied"
	case errors.Is(err, vault.ErrNotFound):
		code, message = 3, "keytab revision was not found"
	}
	fmt.Fprintln(stderr, "secretwright:", message)
	return code
}
