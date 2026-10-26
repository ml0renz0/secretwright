package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/fileformat"
	"github.com/ml0renz0/secretwright/internal/lifecycle"
	"github.com/ml0renz0/secretwright/internal/vault"
)

const lifecycleUsage = `Usage: secretwright lifecycle ACTION [options]

  schema                         Export the JSON Schema offline
  example [--format yaml|json]    Print an editable policy (default YAML)
  validate --file POLICY         Validate a policy offline
  inspect --file POLICY --receipt FILE
  rotate --file POLICY --receipt FILE [--format yaml|json] [--dry-run]
  retire --file POLICY --receipt FILE --ack-consumer
  recover --file POLICY --receipt FILE [--abandon]
  token inspect --file TOKEN
  token renew --file TOKEN --increment DURATION [--if-ttl-below DURATION] [--dry-run]
  lease inspect --file LEASE
  lease renew --file LEASE --increment DURATION [--if-ttl-below DURATION] [--dry-run]
  lease revoke --file LEASE [--force | --dry-run]

Online actions accept --address URL, --namespace NAME, --timeout DURATION and
--token-file FILE for the operator credential. The timeout covers the complete
operation. Target tokens and lease IDs are read only from private files with
mode 0600; lease files contain only lease_id in YAML or JSON. Durations must be
positive whole seconds up to 24h. Files must be real filenames, never '-' or
stdin. Reports contain JSON metadata without credentials or lease IDs.

Rotation is one operation suitable for cron or systemd; it has no scheduler or
daemon. A new receipt uses YAML unless --format json is selected. Existing
receipt encoding is preserved. A successful KV probe verifies the new token,
and does not establish that an application has reloaded it. Retire requires
explicit --ack-consumer before revoking the old token and its descendants.
Recover inspects uncertain checkpoints without replaying issuance, login,
publication or revocation. Retained private artifacts require manual cleanup.
`

var errLifecycleInput = errors.New("could not read the lifecycle input file")
var errLifecycleTarget = errors.New("the lifecycle target is not eligible for this operation")

type lifecycleCommandOptions struct {
	kind       string
	action     string
	file       string
	receipt    string
	format     fileformat.Format
	dryRun     bool
	ack        bool
	abandon    bool
	force      bool
	increment  int64
	below      int64
	network    networkOptions
}

// Share both command depths with session connection injection and its guards.
func lifecycleCommandPrefix(words []string) (string, string, int) {
	if len(words) < 2 || words[0] != "lifecycle" {
		return "", "", 0
	}
	switch words[1] {
	case "schema", "example", "validate", "inspect", "rotate", "retire", "recover":
		return "", words[1], 2
	case "token", "lease":
		if len(words) >= 3 {
			switch words[2] {
			case "inspect", "renew":
				return words[1], words[2], 3
			case "revoke":
				if words[1] == "lease" {
					return words[1], words[2], 3
				}
			}
		}
	}
	return "", "", 0
}

func lifecycleOnline(kind, action string) bool {
	return kind != "" || action == "inspect" || action == "rotate" || action == "retire" || action == "recover"
}

func lifecycleSeconds(value time.Duration) (int64, bool) {
	if value <= 0 || value > 24*time.Hour || value%time.Second != 0 {
		return 0, false
	}
	return int64(value / time.Second), true
}

func parseLifecycleCommandOptions(words []string) (lifecycleCommandOptions, bool, error) {
	var options lifecycleCommandOptions
	var depth int
	options.kind, options.action, depth = lifecycleCommandPrefix(words)
	if depth == 0 {
		return options, false, errInvalidOptions
	}
	flags := flag.NewFlagSet("secretwright lifecycle", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if options.action != "schema" && options.action != "example" {
		flags.StringVar(&options.file, "file", "", "policy or private target file")
	}
	var address, namespace, encoding string
	var timeout, increment, below time.Duration
	if lifecycleOnline(options.kind, options.action) {
		flags.StringVar(&address, "address", "", "Vault URL")
		flags.StringVar(&namespace, "namespace", "", "Vault namespace")
		flags.DurationVar(&timeout, "timeout", 0, "complete operation timeout")
		flags.StringVar(&options.network.tokenFile, "token-file", "", "operator token file")
		if options.kind == "" {
			flags.StringVar(&options.receipt, "receipt", "", "private rotation receipt")
		}
	}
	if options.kind == "" && (options.action == "example" || options.action == "rotate") {
		flags.StringVar(&encoding, "format", "", "yaml or json")
	}
	if options.action == "rotate" || options.action == "renew" || options.action == "revoke" {
		flags.BoolVar(&options.dryRun, "dry-run", false, "inspect without mutation")
	}
	if options.action == "retire" {
		flags.BoolVar(&options.ack, "ack-consumer", false, "acknowledge application credential adoption")
	}
	if options.action == "recover" {
		flags.BoolVar(&options.abandon, "abandon", false, "explicitly abandon eligible unpublished issuance")
	}
	if options.kind == "lease" && options.action == "revoke" {
		flags.BoolVar(&options.force, "force", false, "acknowledge exact lease revocation")
	}
	if options.action == "renew" {
		flags.DurationVar(&increment, "increment", 0, "requested renewal duration")
		flags.DurationVar(&below, "if-ttl-below", 0, "renew only below this TTL")
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
			invalid = invalid || options.network.tokenFile == "" || options.network.tokenFile == "-"
		case "format":
			var err error
			options.format, err = fileformat.Parse(encoding)
			invalid = invalid || err != nil || encoding == ""
		case "if-ttl-below":
			var valid bool
			options.below, valid = lifecycleSeconds(below)
			invalid = invalid || !valid
		}
	})
	if options.action != "schema" && options.action != "example" {
		invalid = invalid || options.file == "" || options.file == "-"
	}
	if options.kind == "" && lifecycleOnline(options.kind, options.action) {
		invalid = invalid || options.receipt == "" || options.receipt == "-"
	}
	if options.action == "renew" {
		var valid bool
		options.increment, valid = lifecycleSeconds(increment)
		invalid = invalid || !valid
	}
	invalid = invalid || options.action == "retire" && !options.ack
	invalid = invalid || options.action == "revoke" && !options.force && !options.dryRun
	if invalid {
		return options, false, errInvalidOptions
	}
	return options, false, nil
}

// Compare lstat/open evidence before accepting either configuration or a private
// lease document; opening a pipe or following a replacement link is not allowed.
func openLifecycleInput(path string, private bool) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || private && before.Mode() != 0o600 {
		return nil, errLifecycleInput
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errLifecycleInput
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || private && after.Mode() != 0o600 {
		file.Close()
		return nil, errLifecycleInput
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(after, current) || private && current.Mode() != 0o600 {
		file.Close()
		return nil, errLifecycleInput
	}
	return file, nil
}

func loadLifecyclePolicy(path string) (lifecycle.Spec, error) {
	file, err := openLifecycleInput(path, false)
	if err != nil {
		return lifecycle.Spec{}, err
	}
	defer file.Close()
	return lifecycle.Load(file)
}

func loadLifecycleLease(path string) (string, error) {
	file, err := openLifecycleInput(path, true)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > 64*1024 {
		return "", errLifecycleInput
	}
	body, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(body) > 64*1024 {
		return "", errLifecycleInput
	}
	document, err := blueprint.DecodeConfiguration(bytes.NewReader(body))
	if err != nil || len(document) != 1 {
		return "", errLifecycleInput
	}
	id, ok := document["lease_id"].(string)
	if !ok || vault.ValidateLifecycleLeaseID(id) != nil {
		return "", errLifecycleInput
	}
	return id, nil
}

func lifecycleCommand(ctx context.Context, words []string, stdout, stderr io.Writer) int {
	if len(words) == 1 || len(words) == 2 && lifecycleHelpWord(words[1]) || len(words) == 3 && (words[1] == "token" || words[1] == "lease") && lifecycleHelpWord(words[2]) {
		return writeUsage(stdout, stderr, lifecycleUsage)
	}
	options, help, err := parseLifecycleCommandOptions(words)
	if help {
		return writeUsage(stdout, stderr, lifecycleUsage)
	}
	if err != nil {
		return lifecycleError(stderr, err)
	}
	if options.kind != "" {
		return lifecycleTargetCommand(ctx, options, stdout, stderr)
	}
	if options.action == "schema" {
		return writeLifecycleBytes(stdout, stderr, lifecycle.Schema())
	}
	if options.action == "example" {
		format := options.format
		if format == "" {
			format = fileformat.YAML
		}
		body, err := fileformat.EncodeJSON(lifecycle.Example(), format)
		if err != nil {
			return lifecycleError(stderr, err)
		}
		return writeLifecycleBytes(stdout, stderr, body)
	}
	spec, err := loadLifecyclePolicy(options.file)
	if err != nil {
		return lifecycleError(stderr, err)
	}
	if options.action == "validate" {
		return writeLifecycleJSON(stdout, stderr, struct {
			Name string `json:"name"`
			Valid bool `json:"valid"`
		}{Name: spec.Name, Valid: true})
	}
	return lifecycleRotationCommand(ctx, options, spec, stdout, stderr)
}

func lifecycleHelpWord(value string) bool {
	return value == "help" || value == "-h" || value == "--help"
}

func lifecycleRotationCommand(ctx context.Context, options lifecycleCommandOptions, spec lifecycle.Spec, stdout, stderr io.Writer) (code int) {
	writable := options.action != "inspect" && !options.dryRun
	store, err := lifecycle.Open(spec, options.receipt, options.format, writable)
	if err != nil {
		return lifecycleError(stderr, err)
	}
	initial := store.Snapshot().Revision
	defer func() {
		if closeErr := store.Close(); closeErr != nil && code == 0 {
			if store.Snapshot().Revision != initial {
				closeErr = errors.Join(lifecycle.ErrPartial, closeErr)
			}
			code = lifecycleError(stderr, closeErr)
		}
	}()
	operator, err := vault.LoadToken(options.network.tokenFile)
	if err != nil {
		return lifecycleError(stderr, err)
	}
	client, err := vault.New(options.network.vault)
	if err != nil {
		return lifecycleError(stderr, err)
	}
	ctx, cancel := context.WithTimeout(ctx, client.OperationTimeout())
	defer cancel()
	backend := lifecycle.NewVaultBackend(client, operator)
	var report lifecycle.Report
	switch options.action {
	case "inspect":
		report, err = lifecycle.Inspect(ctx, spec, store, backend)
	case "rotate":
		report, err = lifecycle.Rotate(ctx, spec, store, backend, options.dryRun)
	case "retire":
		report, err = lifecycle.Retire(ctx, spec, store, backend, options.ack)
	case "recover":
		report, err = lifecycle.Recover(ctx, spec, store, backend, options.abandon)
	}
	if err == nil || report.Name != "" {
		if outputCode := writeLifecycleJSON(stdout, stderr, report); outputCode != 0 {
			return outputCode
		}
	}
	if err != nil {
		return lifecycleError(stderr, err)
	}
	return 0
}

type lifecycleTargetReport struct {
	Operation string `json:"operation"`
	Status string `json:"status"`
	Exists bool `json:"exists"`
	TTLSeconds int64 `json:"ttl_seconds"`
	Renewable bool `json:"renewable"`
}

func lifecycleTargetCommand(ctx context.Context, options lifecycleCommandOptions, stdout, stderr io.Writer) int {
	var target string
	if options.kind == "token" {
		file, err := lifecycle.ReadPrivate(options.file)
		if err != nil {
			return lifecycleError(stderr, err)
		}
		target = file.Token
	} else {
		var err error
		target, err = loadLifecycleLease(options.file)
		if err != nil {
			return lifecycleError(stderr, err)
		}
	}
	operator, err := vault.LoadToken(options.network.tokenFile)
	if err != nil {
		return lifecycleError(stderr, err)
	}
	client, err := vault.New(options.network.vault)
	if err != nil {
		return lifecycleError(stderr, err)
	}
	ctx, cancel := context.WithTimeout(ctx, client.OperationTimeout())
	defer cancel()
	report := lifecycleTargetReport{Operation: options.kind + "_" + options.action}
	if options.kind == "token" {
		info, err := client.InspectLifecycleToken(ctx, operator, target)
		if err != nil {
			return lifecycleError(stderr, err)
		}
		if info.Exists && !eligibleLifecycleToken(info) {
			return lifecycleError(stderr, errLifecycleTarget)
		}
		report.Exists, report.TTLSeconds, report.Renewable = info.Exists, info.TTLSeconds, info.Renewable
		if options.action == "renew" && info.Exists {
			if !info.Renewable || info.NumUses != 0 {
				return lifecycleError(stderr, errLifecycleTarget)
			}
			if options.below != 0 && info.TTLSeconds >= options.below {
				report.Status = "not_due"
			} else if options.dryRun {
				report.Status = "would_renew"
			} else {
				info, err = client.RenewLifecycleToken(ctx, operator, target, options.increment)
				if err != nil {
					return lifecycleError(stderr, err)
				}
				report.Exists, report.TTLSeconds, report.Renewable = info.Exists, info.TTLSeconds, info.Renewable
				report.Status = "renewed"
			}
		}
	} else {
		info, err := client.InspectLifecycleLease(ctx, operator, target)
		if err != nil {
			return lifecycleError(stderr, err)
		}
		report.Exists, report.TTLSeconds, report.Renewable = info.Exists, info.TTLSeconds, info.Renewable
		if options.action == "renew" && info.Exists {
			if !info.Renewable || info.TTLSeconds <= 0 {
				return lifecycleError(stderr, errLifecycleTarget)
			}
			if options.below != 0 && info.TTLSeconds >= options.below {
				report.Status = "not_due"
			} else if options.dryRun {
				report.Status = "would_renew"
			} else {
				info, err = client.RenewLifecycleLease(ctx, operator, target, options.increment)
				if err != nil {
					return lifecycleError(stderr, err)
				}
				report.Exists, report.TTLSeconds, report.Renewable = info.Exists, info.TTLSeconds, info.Renewable
				report.Status = "renewed"
			}
		} else if options.action == "revoke" && info.Exists {
			if options.dryRun {
				report.Status = "would_revoke"
			} else {
				info, err = client.RevokeLifecycleLease(ctx, operator, target)
				if err != nil {
					return lifecycleError(stderr, err)
				}
				report.Exists, report.TTLSeconds, report.Renewable = info.Exists, info.TTLSeconds, info.Renewable
				report.Status = "revoked"
			}
		}
	}
	if report.Status == "" {
		report.Status = "present"
		if !report.Exists {
			report.Status = "missing"
		}
	}
	return writeLifecycleJSON(stdout, stderr, report)
}

func eligibleLifecycleToken(info vault.TokenLifecycleInfo) bool {
	if info.Type != "service" || info.TTLSeconds <= 0 {
		return false
	}
	for _, policies := range [][]string{info.Policies, info.IdentityPolicies} {
		for _, policy := range policies {
			if policy == "root" {
				return false
			}
		}
	}
	return true
}

func writeLifecycleJSON(stdout, stderr io.Writer, value any) int {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return lifecycleError(stderr, err)
	}
	return writeLifecycleBytes(stdout, stderr, append(body, '\n'))
}

func writeLifecycleBytes(stdout, stderr io.Writer, body []byte) int {
	written, err := stdout.Write(body)
	if err != nil || written != len(body) {
		fmt.Fprintln(stderr, "secretwright: could not write lifecycle output")
		return 1
	}
	return 0
}

// Public diagnostics are fixed messages: neither SDK errors nor file paths can
// cross this boundary, including on configuration and local checkpoint errors.
func lifecycleError(stderr io.Writer, err error) int {
	code, message := 1, "invalid lifecycle options, configuration, input or response"
	switch {
	case errors.Is(err, lifecycle.ErrPartial), errors.Is(err, lifecycle.ErrUnconfirmed), errors.Is(err, vault.ErrAccessUnconfirmed), errors.Is(err, vault.ErrAccessPartial):
		code, message = 5, "lifecycle outcome requires inspection before retrying"
	case errors.Is(err, lifecycle.ErrConflict), errors.Is(err, vault.ErrConflict):
		code, message = 4, "lifecycle binding, file or checkpoint conflict"
	case errors.Is(err, context.Canceled):
		code, message = 130, "lifecycle operation canceled"
	case errors.Is(err, vault.ErrPermissionDenied), errors.Is(err, vault.ErrUnauthenticated):
		code, message = 2, "lifecycle authentication or permission denied"
	case errors.Is(err, vault.ErrNotFound):
		code, message = 3, "lifecycle target was not found"
	}
	fmt.Fprintln(stderr, "secretwright:", message)
	return code
}
