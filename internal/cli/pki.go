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
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ml0renz0/secretwright/internal/fileformat"
	"github.com/ml0renz0/secretwright/internal/pki"
	"github.com/ml0renz0/secretwright/internal/vault"
)

const pkiUsage = `Usage: secretwright pki ACTION [options]

  schema                       Export the request JSON Schema offline
  example [--format yaml|json] Print an editable request (default YAML)
  validate --file REQUEST      Validate a request offline
  cert inspect --file CERT.pem
  cert verify --file CERT.pem --ca-file ROOTS.pem [--chain CHAIN.pem]
              [--hostname NAME] [--usage server-auth|client-auth]
  cert match --file CERT.pem --key KEY.pem
  key inspect --file KEY.pem
  csr inspect --file CSR.pem
  csr create --file REQUEST --out CSR.pem --key-out KEY.pem
  ca --mount PKI --out CA.pem
  read --mount PKI --serial HEX --out CERT.pem
  issue --mount PKI --role ROLE --file REQUEST --ca-file ROOTS.pem --out IDENTITY.pem
  sign --mount PKI --role ROLE --file REQUEST --csr CSR.pem --ca-file ROOTS.pem --out CERT.pem
  revoke --mount PKI --file CERT.pem --force

Schema, example, validate and cert/key/csr commands run offline. Certificate
verification requires explicit roots, checks only the selected usage/name/time,
and does not check revocation or download AIA, OCSP or CRL resources.

CA/read/issue/sign/revoke accept --address URL, --namespace NAME, --timeout
DURATION and --token-file FILE. The timeout covers the complete operation.
Mounts and issuance roles must already exist. Signing sends only the CSR; the
local private key is never uploaded. Revoke targets the exact supplied leaf.

All inputs are real filenames, never '-' or stdin. Keys and identity bundles
must be private regular files (0600). Outputs must not exist and are saved as
private PEM files. CSR creation reserves both outputs, saves the key first and
retains it if saving the CSR fails. Structured examples default to YAML, with
JSON optional; PEM files retain their standard encoding. Reports are JSON
metadata and never contain PEM material. All PKI commands stay out of history.

Issuance and signing are never retried or automatically compensated. Exit 5
means a certificate may have been issued or an output was only partly saved;
inspect the artifacts and Vault before explicitly retrying or revoking.
`

var errPKIOutputConflict = errors.New("the PKI output must not already exist")

type pkiCommandOptions struct {
	kind      string
	action    string
	file      string
	caFile    string
	chain     string
	key       string
	csr       string
	output    string
	keyOutput string
	hostname  string
	usage     string
	mount     string
	role      string
	serial    string
	format    fileformat.Format
	force     bool
	network   networkOptions
}

// Keep the shell's connection insertion and override scan aligned with parsing.
func pkiCommandPrefix(words []string) (string, string, int) {
	if len(words) < 2 || words[0] != "pki" {
		return "", "", 0
	}
	switch words[1] {
	case "schema", "example", "validate", "ca", "read", "issue", "sign", "revoke":
		return "", words[1], 2
	case "cert", "key", "csr":
		if len(words) < 3 {
			return "", "", 0
		}
		kind, action := words[1], words[2]
		if action == "inspect" || kind == "cert" && (action == "verify" || action == "match") || kind == "csr" && action == "create" {
			return kind, action, 3
		}
	}
	return "", "", 0
}

func pkiOnline(kind, action string) bool {
	if kind != "" {
		return false
	}
	switch action {
	case "ca", "read", "issue", "sign", "revoke":
		return true
	}
	return false
}

func pkiRoleName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	for index, character := range name {
		letterOrDigit := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
		if !letterOrDigit && (index == 0 || character != '_' && character != '-' && character != '.') {
			return false
		}
	}
	return true
}

func pkiFilename(name string) bool {
	return name != "" && name != "-" && len(name) <= 4096 && utf8.ValidString(name) && strings.IndexFunc(name, unicode.IsControl) < 0
}

func parsePKICommandOptions(words []string) (pkiCommandOptions, bool, error) {
	var options pkiCommandOptions
	var depth int
	options.kind, options.action, depth = pkiCommandPrefix(words)
	if depth == 0 {
		return options, false, errInvalidOptions
	}
	flags := flag.NewFlagSet("secretwright pki", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	fileRequired := options.kind != "" || options.action == "validate" || options.action == "issue" || options.action == "sign" || options.action == "revoke"
	if fileRequired {
		flags.StringVar(&options.file, "file", "", "request, certificate, private key or CSR file")
	}
	var address, namespace, encoding string
	var timeout time.Duration
	if pkiOnline(options.kind, options.action) {
		flags.StringVar(&options.mount, "mount", "", "explicit PKI mount")
		flags.StringVar(&address, "address", "", "Vault URL")
		flags.StringVar(&namespace, "namespace", "", "Vault namespace")
		flags.DurationVar(&timeout, "timeout", 0, "complete operation timeout")
		flags.StringVar(&options.network.tokenFile, "token-file", "", "operator token file")
	}
	outputRequired := options.kind == "csr" && options.action == "create" || options.kind == "" && (options.action == "ca" || options.action == "read" || options.action == "issue" || options.action == "sign")
	if outputRequired {
		flags.StringVar(&options.output, "out", "", "new private PEM output")
	}
	if options.kind == "csr" && options.action == "create" {
		flags.StringVar(&options.keyOutput, "key-out", "", "new private key output")
	}
	if options.action == "example" {
		flags.StringVar(&encoding, "format", "", "yaml or json")
	}
	if options.kind == "cert" && options.action == "verify" {
		options.usage = "server-auth"
		flags.StringVar(&options.chain, "chain", "", "intermediate certificate PEM file")
		flags.StringVar(&options.hostname, "hostname", "", "DNS name or IP to verify")
		flags.StringVar(&options.usage, "usage", "server-auth", "server-auth or client-auth")
	}
	caRequired := options.kind == "cert" && options.action == "verify" || options.action == "issue" || options.action == "sign"
	if caRequired {
		flags.StringVar(&options.caFile, "ca-file", "", "explicit trusted CA certificates")
	}
	if options.kind == "cert" && options.action == "match" {
		flags.StringVar(&options.key, "key", "", "private key or identity bundle")
	}
	if options.action == "issue" || options.action == "sign" {
		flags.StringVar(&options.role, "role", "", "existing issuance role")
	}
	if options.action == "sign" {
		flags.StringVar(&options.csr, "csr", "", "local CSR PEM file")
	}
	if options.action == "read" {
		flags.StringVar(&options.serial, "serial", "", "exact certificate serial")
	}
	if options.action == "revoke" {
		flags.BoolVar(&options.force, "force", false, "acknowledge exact certificate revocation")
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
			invalid = invalid || !pkiFilename(options.network.tokenFile)
		case "format":
			var err error
			options.format, err = fileformat.Parse(encoding)
			invalid = invalid || encoding == "" || err != nil
		case "chain":
			invalid = invalid || !pkiFilename(options.chain)
		case "hostname":
			invalid = invalid || options.hostname == ""
		}
	})
	invalid = invalid || fileRequired && !pkiFilename(options.file) || outputRequired && !pkiFilename(options.output) || caRequired && !pkiFilename(options.caFile)
	if options.kind == "csr" && options.action == "create" {
		invalid = invalid || !pkiFilename(options.keyOutput) || options.keyOutput == options.output
	}
	if options.kind == "cert" && options.action == "match" {
		invalid = invalid || !pkiFilename(options.key)
	}
	if options.kind == "cert" && options.action == "verify" {
		invalid = invalid || options.usage != "server-auth" && options.usage != "client-auth"
	}
	if pkiOnline(options.kind, options.action) {
		invalid = invalid || vault.ValidatePKIMount(options.mount) != nil
	}
	if options.action == "issue" || options.action == "sign" {
		invalid = invalid || !pkiRoleName(options.role)
	}
	if options.action == "sign" {
		invalid = invalid || !pkiFilename(options.csr)
	}
	if options.action == "read" {
		var err error
		options.serial, err = vault.ValidatePKISerial(options.serial)
		invalid = invalid || err != nil
	}
	invalid = invalid || options.action == "revoke" && !options.force
	if invalid {
		return options, false, errInvalidOptions
	}
	return options, false, nil
}

func pkiHelpWord(word string) bool {
	return word == "help" || word == "-h" || word == "--help"
}

func pkiCommand(ctx context.Context, words []string, stdout, stderr io.Writer) int {
	if len(words) == 1 || len(words) == 2 && pkiHelpWord(words[1]) || len(words) == 3 && (words[1] == "cert" || words[1] == "key" || words[1] == "csr") && pkiHelpWord(words[2]) {
		return writeUsage(stdout, stderr, pkiUsage)
	}
	options, help, err := parsePKICommandOptions(words)
	if help {
		return writeUsage(stdout, stderr, pkiUsage)
	}
	if err != nil {
		return pkiCLIError(stderr, err)
	}
	if options.action == "schema" {
		return writePKIBytes(stdout, stderr, pki.Schema(), false)
	}
	if options.action == "example" {
		body, err := fileformat.EncodeJSON(pki.Example(), options.format)
		if err != nil {
			return pkiCLIError(stderr, err)
		}
		return writePKIBytes(stdout, stderr, body, false)
	}
	if pkiOnline(options.kind, options.action) {
		return pkiVaultCommand(ctx, options, stdout, stderr)
	}
	return pkiOfflineCommand(ctx, options, stdout, stderr)
}

func loadPKISpec(path string) (pki.Spec, error) {
	body, err := readPKIFile(path, false, 1<<20)
	if err != nil {
		return pki.Spec{}, err
	}
	return pki.Load(bytes.NewReader(body))
}

func pkiOfflineCommand(ctx context.Context, options pkiCommandOptions, stdout, stderr io.Writer) int {
	var report any
	var err error
	if options.action == "validate" || options.kind == "csr" && options.action == "create" {
		spec, err := loadPKISpec(options.file)
		if err != nil {
			return pkiCLIError(stderr, err)
		}
		if options.action == "validate" {
			return writePKIJSON(stdout, stderr, struct {
				Name  string `json:"name"`
				Valid bool   `json:"valid"`
			}{Name: spec.Name, Valid: true}, false)
		}
		return pkiCreateCSR(ctx, options, spec, stdout, stderr)
	}
	switch options.kind {
	case "cert":
		certificate, inputErr := readPKICertificates(options.file)
		if inputErr != nil {
			return pkiCLIError(stderr, inputErr)
		}
		switch options.action {
		case "inspect":
			report, err = pki.InspectCertificates(bytes.NewReader(certificate), time.Now().UTC())
		case "match":
			key, inputErr := readPKIKey(options.key)
			if inputErr != nil {
				return pkiCLIError(stderr, inputErr)
			}
			report, err = pki.MatchPrivateKey(bytes.NewReader(certificate), bytes.NewReader(key))
		case "verify":
			roots, inputErr := readPKIFile(options.caFile, false, 1<<20)
			if inputErr != nil || pki.ValidateRoots(roots) != nil {
				return pkiCLIError(stderr, pki.ErrInvalidInput)
			}
			var intermediates io.Reader
			if options.chain != "" {
				chain, inputErr := readPKIFile(options.chain, false, 1<<20)
				if inputErr != nil {
					return pkiCLIError(stderr, inputErr)
				}
				intermediates = bytes.NewReader(chain)
			}
			report, err = pki.VerifyCertificate(bytes.NewReader(certificate), bytes.NewReader(roots), intermediates, pki.VerifyOptions{Name: options.hostname, Usage: options.usage})
		}
	case "key":
		key, inputErr := readPKIKey(options.file)
		if inputErr != nil {
			return pkiCLIError(stderr, inputErr)
		}
		report, err = pki.InspectPrivateKey(bytes.NewReader(key))
	case "csr":
		csr, inputErr := readPKICSR(options.file)
		if inputErr != nil {
			return pkiCLIError(stderr, inputErr)
		}
		report, err = pki.InspectCSR(bytes.NewReader(csr))
	}
	if err == nil || errors.Is(err, pki.ErrVerification) || errors.Is(err, pki.ErrKeyMismatch) {
		if code := writePKIJSON(stdout, stderr, report, false); code != 0 {
			return code
		}
	}
	if err != nil {
		return pkiCLIError(stderr, err)
	}
	return 0
}

func reservePKIOutput(path string) (*credentialOutput, error) {
	if !pkiFilename(path) {
		return nil, errPKIFile
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, errPKIOutputConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errPKIFile
	}
	output, err := reserveCredentialOutput(path)
	if err != nil {
		if _, existsErr := os.Lstat(path); existsErr == nil {
			return nil, errPKIOutputConflict
		}
		return nil, errPKIFile
	}
	return output, nil
}

func pkiOutputPrivate(output *credentialOutput) bool {
	if output == nil || !output.ownsPath() {
		return false
	}
	info, err := os.Lstat(output.filename)
	return err == nil && info.Mode() == 0o600
}

func commitPKIOutput(output *credentialOutput, body []byte) error {
	if !pkiOutputPrivate(output) {
		return errPKIFile
	}
	err := output.commit(func(destination io.Writer) error {
		written, err := destination.Write(body)
		if err != nil || written != len(body) {
			return errPKIFile
		}
		return nil
	})
	if err != nil || !pkiOutputPrivate(output) {
		return errPKIFile
	}
	return nil
}

func pkiCreateCSR(ctx context.Context, options pkiCommandOptions, spec pki.Spec, stdout, stderr io.Writer) int {
	if err := ctx.Err(); err != nil {
		return pkiCLIError(stderr, err)
	}
	keyOutput, err := reservePKIOutput(options.keyOutput)
	if err != nil {
		return pkiCLIError(stderr, err)
	}
	defer keyOutput.abort()
	csrOutput, err := reservePKIOutput(options.output)
	if err != nil {
		return pkiCLIError(stderr, err)
	}
	defer csrOutput.abort()
	generated, err := pki.GenerateCSR(ctx, spec)
	if err != nil {
		return pkiCLIError(stderr, err)
	}
	if err := commitPKIOutput(keyOutput, generated.PrivateKeyPEM); err != nil {
		return pkiCLIError(stderr, err)
	}
	if err := commitPKIOutput(csrOutput, generated.CSRPEM); err != nil {
		return pkiCLIError(stderr, errors.Join(pki.ErrPartial, err))
	}
	return writePKIJSON(stdout, stderr, generated.Report, false)
}

func pkiVaultCommand(ctx context.Context, options pkiCommandOptions, stdout, stderr io.Writer) int {
	var spec pki.Spec
	var roots, csr, certificate []byte
	var err error
	switch options.action {
	case "issue", "sign":
		spec, err = loadPKISpec(options.file)
		if err != nil {
			return pkiCLIError(stderr, err)
		}
		roots, err = readPKIFile(options.caFile, false, 1<<20)
		if err != nil || pki.ValidateRoots(roots) != nil {
			return pkiCLIError(stderr, pki.ErrInvalidInput)
		}
		if options.action == "sign" {
			csr, err = readPKICSR(options.csr)
			if err != nil {
				return pkiCLIError(stderr, err)
			}
			if _, err := pki.ValidateCSR(spec, csr); err != nil {
				return pkiCLIError(stderr, err)
			}
		}
	case "revoke":
		certificate, err = readPKICertificates(options.file)
		if err != nil {
			return pkiCLIError(stderr, err)
		}
		if _, err := pki.CertificateSerial(bytes.NewReader(certificate)); err != nil {
			return pkiCLIError(stderr, err)
		}
	}
	var output *credentialOutput
	if options.action != "revoke" {
		output, err = reservePKIOutput(options.output)
		if err != nil {
			return pkiCLIError(stderr, err)
		}
		defer output.abort()
	}
	if err := ctx.Err(); err != nil {
		return pkiCLIError(stderr, err)
	}
	operator, err := vault.LoadToken(options.network.tokenFile)
	if err != nil {
		return pkiCLIError(stderr, err)
	}
	client, err := vault.New(options.network.vault)
	if err != nil {
		return pkiCLIError(stderr, err)
	}
	ctx, cancel := context.WithTimeout(ctx, client.OperationTimeout())
	defer cancel()
	opts := vault.PKIOptions{Mount: options.mount}
	if options.action == "revoke" {
		report, err := client.RevokePKICertificate(ctx, operator, certificate, opts)
		if err != nil {
			return pkiCLIError(stderr, err)
		}
		return writePKIJSON(stdout, stderr, report, true)
	}
	var issued vault.PKICertificate
	switch options.action {
	case "ca":
		issued, err = client.ReadPKICA(ctx, operator, opts)
	case "read":
		issued, err = client.ReadPKICertificate(ctx, operator, options.serial, opts)
	case "issue":
		issued, err = client.IssuePKICertificate(ctx, operator, options.role, spec, roots, opts)
	case "sign":
		issued, err = client.SignPKICertificate(ctx, operator, options.role, spec, csr, roots, opts)
	}
	if err != nil {
		return pkiCLIError(stderr, err)
	}
	mutation := options.action == "issue" || options.action == "sign"
	if err := commitPKIOutput(output, issued.PEM); err != nil {
		if mutation {
			err = errors.Join(pki.ErrPartial, err)
		}
		return pkiCLIError(stderr, err)
	}
	return writePKIJSON(stdout, stderr, issued.Report, mutation)
}

func writePKIJSON(stdout, stderr io.Writer, report any, mutation bool) int {
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		if mutation {
			err = errors.Join(pki.ErrPartial, err)
		}
		return pkiCLIError(stderr, err)
	}
	return writePKIBytes(stdout, stderr, append(body, '\n'), mutation)
}

func writePKIBytes(stdout, stderr io.Writer, body []byte, mutation bool) int {
	written, err := stdout.Write(body)
	if err != nil || written != len(body) {
		if mutation {
			return pkiCLIError(stderr, pki.ErrPartial)
		}
		fmt.Fprintln(stderr, "secretwright: could not write PKI output")
		return 1
	}
	return 0
}

func pkiCLIError(stderr io.Writer, err error) int {
	code, message := 1, "invalid PKI options, input, configuration or response"
	switch {
	case errors.Is(err, pki.ErrPartial), errors.Is(err, vault.ErrAccessUnconfirmed), errors.Is(err, vault.ErrAccessPartial):
		code, message = 5, "PKI outcome requires inspection before retrying"
	case errors.Is(err, pki.ErrVerification), errors.Is(err, pki.ErrKeyMismatch):
		code, message = 4, "PKI verification or key matching failed"
	case errors.Is(err, errPKIOutputConflict), errors.Is(err, vault.ErrConflict):
		code, message = 4, "PKI output or certificate binding conflict"
	case errors.Is(err, context.Canceled):
		code, message = 130, "PKI operation canceled"
	case errors.Is(err, vault.ErrPermissionDenied), errors.Is(err, vault.ErrUnauthenticated):
		code, message = 2, "PKI authentication or permission denied"
	case errors.Is(err, vault.ErrNotFound):
		code, message = 3, "PKI certificate or resource was not found"
	}
	fmt.Fprintln(stderr, "secretwright:", message)
	return code
}
