package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/managedstate"
	"github.com/ml0renz0/secretwright/internal/vault"
)

const blueprintUsage = `Usage: secretwright blueprint ACTION [options]

  schema                              Export the embedded JSON Schema offline
  validate --file BP.yaml [--vars FILE] Validate a blueprint offline
  plan --file BP.yaml [--vars FILE]     Inspect Vault and print resource metadata
  apply --file BP.yaml [--vars FILE]    Create missing resources in dependency order
  adopt --file BP.yaml --state NEW     Explicitly record equivalent resources
  recover --file BP.yaml --state FILE  Inspect and recover pending checkpoints

Plan/apply accept --state FILE for managed reconciliation. External drift is
blocked unless --repair is selected. Recover --adopt-pending explicitly claims
an equivalent resource after an uncertain creation. State files are private
metadata, bound to the selected cluster, namespace and address. Omitted resources
are retained, never deleted. Administrative updates have no atomic CAS.

Plan, apply, adopt and recover accept --address URL, --namespace NAME,
--timeout DURATION and
--token-file FILE. The timeout covers the complete operation. These commands
have no KV working directory. Schema and validate do not select credentials,
inspect network configuration or contact Vault.

Files must be actual filenames, never '-' or stdin. Variables are non-secret
configuration, supplied explicitly; no environment or secret lookup occurs.
Plans contain metadata, not policy bodies, specifications or variable values.

Existing equivalent resources are unchanged. A differing or incompatible
resource causes exit 4 before any write. Without --state, apply builds a fresh
create-only plan. Managed apply may update explicitly owned configuration;
neither mode deletes, migrates engines or issues credentials. Administrative APIs
have no atomic CAS, and a concurrent change can still occur between inspection
and creation. Exit 5 means earlier or unconfirmed changes require inspection;
there is no automatic rollback or retry.
`

var errReadBlueprint = errors.New("could not read the blueprint or variables file")

type blueprintCommandOptions struct {
	action       string
	file         string
	variables    string
	state        string
	repair       bool
	adoptPending bool
	network      networkOptions
}

// Share the command depth with shell injection and override detection. Only
// plan/apply use the session connection; schema/validate remain offline.
func blueprintCommandPrefix(words []string) (string, int) {
	if len(words) < 2 || words[0] != "blueprint" {
		return "", 0
	}
	switch words[1] {
	case "schema", "validate", "plan", "apply", "adopt", "recover":
		return words[1], 2
	default:
		return "", 0
	}
}

func parseBlueprintCommandOptions(words []string) (blueprintCommandOptions, bool, error) {
	var options blueprintCommandOptions
	var depth int
	options.action, depth = blueprintCommandPrefix(words)
	if depth == 0 {
		return options, false, errInvalidOptions
	}
	flags := flag.NewFlagSet("secretwright blueprint", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if options.action != "schema" {
		flags.StringVar(&options.file, "file", "", "blueprint file")
		flags.StringVar(&options.variables, "vars", "", "explicit variable file")
	}
	var address, namespace string
	var timeout time.Duration
	if blueprintOnline(options.action) {
		flags.StringVar(&options.state, "state", "", "private managed inventory file")
		flags.StringVar(&address, "address", "", "Vault URL")
		flags.StringVar(&namespace, "namespace", "", "Vault namespace")
		flags.DurationVar(&timeout, "timeout", 0, "complete operation timeout")
		flags.StringVar(&options.network.tokenFile, "token-file", "", "operator token file")
	}
	if options.action == "plan" || options.action == "apply" {
		flags.BoolVar(&options.repair, "repair", false, "repair managed external drift")
	}
	if options.action == "recover" {
		flags.BoolVar(&options.adoptPending, "adopt-pending", false, "claim an equivalent uncertain creation")
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
			invalid = invalid || options.network.tokenFile == ""
		case "vars":
			invalid = invalid || options.variables == "" || options.variables == "-"
		case "state":
			invalid = invalid || options.state == "" || options.state == "-"
		case "repair":
			invalid = invalid || options.state == ""
		}
	})
	if (options.action == "adopt" || options.action == "recover") && options.state == "" {
		invalid = true
	}
	if options.action != "schema" && (options.file == "" || options.file == "-") {
		invalid = true
	}
	if invalid {
		return options, false, errInvalidOptions
	}
	return options, false, nil
}

func loadBlueprintCommandInput(options blueprintCommandOptions) (blueprint.Document, error) {
	file, err := os.Open(options.file)
	if err != nil {
		return blueprint.Document{}, errReadBlueprint
	}
	defer file.Close()
	var variables io.Reader
	if options.variables != "" {
		selected, err := os.Open(options.variables)
		if err != nil {
			return blueprint.Document{}, errReadBlueprint
		}
		defer selected.Close()
		variables = selected
	}
	document, err := blueprint.Load(file, variables)
	if err != nil {
		return blueprint.Document{}, blueprint.ErrInvalidBlueprint
	}
	return document, nil
}

func blueprintCommand(ctx context.Context, words []string, stdout, stderr io.Writer) int {
	if len(words) == 1 || len(words) == 2 && (words[1] == "help" || words[1] == "-h" || words[1] == "--help") {
		return writeUsage(stdout, stderr, blueprintUsage)
	}
	options, help, err := parseBlueprintCommandOptions(words)
	if help {
		return writeUsage(stdout, stderr, blueprintUsage)
	}
	if err != nil {
		return commandError(stderr, err)
	}
	if options.action == "schema" {
		body := blueprint.Schema()
		written, err := stdout.Write(body)
		if err != nil || written != len(body) {
			return commandError(stderr, errors.New("could not write the blueprint schema"))
		}
		return 0
	}
	document, err := loadBlueprintCommandInput(options)
	if err != nil {
		return blueprintError(stderr, err)
	}
	if options.action == "validate" {
		return writeJSON(stdout, stderr, blueprint.ValidationReport{Name: document.Name, Resources: len(document.Resources), Order: document.Order})
	}
	if options.state != "" {
		return managedBlueprintCommand(ctx, options, document, stdout, stderr)
	}
	token, err := vault.LoadToken(options.network.tokenFile)
	if err != nil {
		return blueprintError(stderr, err)
	}
	client, err := vault.New(options.network.vault)
	if err != nil {
		return blueprintError(stderr, err)
	}
	ctx, cancel := context.WithTimeout(ctx, client.OperationTimeout())
	defer cancel()
	backend := blueprint.NewVaultBackend(client, token)
	if options.action == "plan" {
		plan, err := blueprint.BuildPlan(ctx, document, backend)
		if err != nil {
			if errors.Is(err, blueprint.ErrConflict) && len(plan.Resources) != 0 {
				if code := writeJSON(stdout, stderr, plan); code != 0 {
					return code
				}
			}
			return blueprintError(stderr, err)
		}
		return writeJSON(stdout, stderr, plan)
	}
	report, err := blueprint.Apply(ctx, document, backend)
	if err != nil {
		if len(report.Items) != 0 {
			if code := writeJSON(stdout, stderr, report); code != 0 {
				return code
			}
		}
		return blueprintError(stderr, err)
	}
	return writeJSON(stdout, stderr, report)
}

func blueprintError(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "secretwright:", err)
	switch {
	case errors.Is(err, blueprint.ErrPartial), errors.Is(err, blueprint.ErrUnconfirmed), errors.Is(err, vault.ErrAccessUnconfirmed), errors.Is(err, managedstate.ErrStateUnconfirmed):
		return 5
	case errors.Is(err, blueprint.ErrConflict), errors.Is(err, blueprint.ErrStateConflict), errors.Is(err, vault.ErrConflict), errors.Is(err, managedstate.ErrStateLocked), errors.Is(err, managedstate.ErrStateChanged):
		return 4
	case errors.Is(err, context.Canceled):
		return 130
	case errors.Is(err, vault.ErrPermissionDenied), errors.Is(err, vault.ErrUnauthenticated):
		return 2
	case errors.Is(err, vault.ErrNotFound):
		return 3
	default:
		return 1
	}
}
