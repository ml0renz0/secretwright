// Package cli provides the noninteractive command interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

const usage = `Secretwright — interactive shell and declarative secrets lifecycle management.

Usage:
  secretwright help                 Show this help
  secretwright version              Show the build version
  secretwright status [options]     Print Vault health as JSON (no token required)
  secretwright auth check [options] Check token authentication as JSON

Network options (after status or auth check):
  --address URL           Override VAULT_ADDR and VAULT_AGENT_ADDR
  --namespace NAME        Override VAULT_NAMESPACE; an empty value selects root
  --timeout DURATION      Request timeout, for example 5s or 1m

Authentication option (after auth check only):
  --token-file PATH       Read a token from this file instead of VAULT_TOKEN

Configuration:
  VAULT_ADDR               Vault URL (default: https://127.0.0.1:8200)
  VAULT_AGENT_ADDR         Optional Vault Agent URL (takes precedence over VAULT_ADDR)
  VAULT_CACERT             Trusted CA certificate file
  VAULT_CAPATH             Trusted CA certificate directory
  VAULT_CLIENT_CERT        TLS client certificate file
  VAULT_CLIENT_KEY         TLS client private key file
  VAULT_TLS_SERVER_NAME    TLS server name override
  VAULT_NAMESPACE          Vault namespace
  VAULT_CLIENT_TIMEOUT     Request timeout (default: 10s)
  VAULT_TOKEN              Token used only by auth check

Status exit codes: 0 initialized and unsealed; 2 sealed or uninitialized;
1 configuration, request, or output error.
Auth check exit codes: 0 authenticated; 2 no token or lookup-self denied;
1 configuration, request, or output error.

Tokens are not accepted as command-line arguments or saved to disk.
The interactive shell and declarative operations are planned.
`

const statusUsage = `Usage: secretwright status [--address URL] [--namespace NAME] [--timeout DURATION]

Print Vault health as JSON without sending token credentials.
Network options override the corresponding environment configuration.
Run secretwright help for configuration variables and exit codes.
`

const authUsage = `Usage: secretwright auth check [--address URL] [--namespace NAME] [--timeout DURATION] [--token-file PATH]

Check a token using Vault's lookup-self endpoint and print authentication metadata.
Read the token from --token-file when supplied, otherwise from VAULT_TOKEN.
No token is accepted as an argument, displayed, or saved to disk.
Run secretwright help for configuration variables and exit codes.
`

var errInvalidOptions = errors.New("invalid command options; run secretwright help")

// Run executes one command and returns a process exit code. It does not close
// streams or terminate the process, which lets acceptance tests use real HTTP.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, version string) int {
	if len(args) == 0 {
		return writeHelp(stdout, stderr)
	}
	switch args[0] {
	case "help", "-h", "--help":
		if len(args) != 1 {
			return commandError(stderr, errInvalidOptions)
		}
		return writeHelp(stdout, stderr)
	case "version", "--version":
		if len(args) != 1 {
			return commandError(stderr, errInvalidOptions)
		}
		if _, err := fmt.Fprintf(stdout, "secretwright %s\n", version); err != nil {
			fmt.Fprintln(stderr, "secretwright: could not write output")
			return 1
		}
		return 0
	case "status":
		return status(ctx, args[1:], stdout, stderr)
	case "auth":
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h" || args[1] == "help") {
			return writeUsage(stdout, stderr, authUsage)
		}
		if len(args) < 2 || args[1] != "check" {
			return commandError(stderr, errInvalidOptions)
		}
		return authCheck(ctx, args[2:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, "secretwright: unknown command; run secretwright help")
		return 1
	}
}

func writeHelp(stdout, stderr io.Writer) int {
	return writeUsage(stdout, stderr, usage)
}

func writeUsage(stdout, stderr io.Writer, text string) int {
	if _, err := io.WriteString(stdout, text); err != nil {
		fmt.Fprintln(stderr, "secretwright: could not write output")
		return 1
	}
	return 0
}

type networkOptions struct {
	vault     vault.Options
	tokenFile string
}

// parseNetworkOptions discards flag package diagnostics because they echo input
// values. Only explicitly visited options override the environment, including an
// explicitly empty namespace.
func parseNetworkOptions(args []string, authentication bool) (networkOptions, bool, error) {
	var options networkOptions
	var address, namespace string
	var timeout time.Duration
	flags := flag.NewFlagSet("secretwright", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&address, "address", "", "Vault URL")
	flags.StringVar(&namespace, "namespace", "", "Vault namespace")
	flags.DurationVar(&timeout, "timeout", 0, "request timeout")
	if authentication {
		flags.StringVar(&options.tokenFile, "token-file", "", "token file")
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return options, true, nil
		}
		return options, false, errInvalidOptions
	}
	if flags.NArg() != 0 {
		return options, false, errInvalidOptions
	}
	invalidTokenFile := false
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "address":
			options.vault.Address = &address
		case "namespace":
			options.vault.Namespace = &namespace
		case "timeout":
			options.vault.Timeout = &timeout
		case "token-file":
			invalidTokenFile = options.tokenFile == ""
		}
	})
	if invalidTokenFile {
		return options, false, errInvalidOptions
	}
	return options, false, nil
}

func commandError(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "secretwright:", err)
	return 1
}

func status(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	options, help, err := parseNetworkOptions(args, false)
	if help {
		return writeUsage(stdout, stderr, statusUsage)
	}
	if err != nil {
		return commandError(stderr, err)
	}
	client, err := vault.New(options.vault)
	if err != nil {
		return commandError(stderr, err)
	}
	report, err := client.Status(ctx)
	if err != nil {
		return commandError(stderr, err)
	}
	if code := writeJSON(stdout, stderr, report); code != 0 {
		return code
	}
	if !report.Initialized || report.Sealed {
		return 2
	}
	return 0
}

func authCheck(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	options, help, err := parseNetworkOptions(args, true)
	if help {
		return writeUsage(stdout, stderr, authUsage)
	}
	if err != nil {
		return commandError(stderr, err)
	}
	token, err := vault.LoadToken(options.tokenFile)
	if err != nil {
		return authenticationError(stderr, err)
	}
	client, err := vault.New(options.vault)
	if err != nil {
		return commandError(stderr, err)
	}
	report, err := client.CheckToken(ctx, token)
	if err != nil {
		return authenticationError(stderr, err)
	}
	return writeJSON(stdout, stderr, report)
}

func authenticationError(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "secretwright:", err)
	if errors.Is(err, vault.ErrUnauthenticated) {
		return 2
	}
	return 1
}

func writeJSON(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintln(stderr, "secretwright: could not write output")
		return 1
	}
	return 0
}
