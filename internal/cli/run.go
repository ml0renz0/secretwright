// Package cli provides the noninteractive bootstrap command interface.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

const usage = `Secretwright — interactive shell and declarative secrets lifecycle management.

Usage:
  secretwright help       Show this help
  secretwright version    Show the build version
  secretwright status     Print Vault health as JSON (read-only, no token required)

Configuration:
  VAULT_ADDR              Vault URL (default: https://127.0.0.1:8200)
  VAULT_AGENT_ADDR        Optional Vault Agent URL (takes precedence over VAULT_ADDR)
  VAULT_CACERT             Trusted CA certificate file
  VAULT_CAPATH             Trusted CA certificate directory
  VAULT_CLIENT_CERT        TLS client certificate file
  VAULT_CLIENT_KEY         TLS client private key file
  VAULT_TLS_SERVER_NAME    TLS server name override
  VAULT_NAMESPACE          Vault namespace

Status exit codes: 0 initialized and unsealed; 2 sealed or uninitialized;
1 configuration, request, or output error. Requests time out after 10 seconds.

F00 bootstrap: the interactive shell and declarative operations are planned.
`

// Run executes one command and returns a process exit code. It does not close
// streams or terminate the process, which lets acceptance tests use real HTTP.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, version string) int {
	if len(args) == 0 {
		return writeHelp(stdout, stderr)
	}
	if len(args) != 1 {
		fmt.Fprintln(stderr, "secretwright: expected one command; run secretwright help")
		return 1
	}
	switch args[0] {
	case "help", "-h", "--help":
		return writeHelp(stdout, stderr)
	case "version", "--version":
		if _, err := fmt.Fprintf(stdout, "secretwright %s\n", version); err != nil {
			fmt.Fprintln(stderr, "secretwright: could not write output")
			return 1
		}
		return 0
	case "status":
		return status(ctx, stdout, stderr)
	default:
		fmt.Fprintln(stderr, "secretwright: unknown command; run secretwright help")
		return 1
	}
}

func writeHelp(stdout, stderr io.Writer) int {
	if _, err := io.WriteString(stdout, usage); err != nil {
		fmt.Fprintln(stderr, "secretwright: could not write output")
		return 1
	}
	return 0
}

func status(ctx context.Context, stdout, stderr io.Writer) int {
	client, err := vault.NewFromEnvironment()
	if err != nil {
		fmt.Fprintln(stderr, "secretwright:", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	report, err := client.Status(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "secretwright:", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(stderr, "secretwright: could not write output")
		return 1
	}
	if !report.Initialized || report.Sealed {
		return 2
	}
	return 0
}
