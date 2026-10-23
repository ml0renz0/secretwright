package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ml0renz0/secretwright/internal/vault"
)

const accessUsage = `Usage: secretwright ACCESS-GROUP ACTION [options] [NAME|ID|PATH...]

  policy list | read NAME | write --file POLICY.hcl NAME | delete --force NAME
  approle list | read NAME | write --file ROLE.json NAME | delete --force NAME
  approle role-id --out FILE NAME
  approle credentials --out FILE NAME
  approle revoke-secret-id --file BUNDLE.json NAME
  approle login --file BUNDLE.json --out TOKENFILE
  token create --file SPEC.json --out TOKENFILE
  token revoke --force --file TARGETTOKENFILE
  token revoke-self --force
  token capabilities PATH...
  identity entity list | read ID | write --file SPEC.json [ID] | delete --force ID
  identity group list | read ID | write --file SPEC.json [ID] | delete --force ID

Options follow the deepest action and precede positional arguments:
  --address URL, --namespace NAME, --timeout DURATION, --token-file FILE.
AppRole actions also accept --auth-mount PATH (default: approle).
AppRole login is anonymous and rejects --token-file. It never changes the
environment, selected token or shell session. Access commands have no KV cwd.

Inputs require actual files; '-' and stdin are not supported. Credential outputs
reserve a new private file with mode 0600 before requests. That file can be empty
while issuance runs; existing files and symlinks are never replaced. Only safe
metadata is printed. Tokens use a raw line compatible with --token-file; AppRole
credential bundles contain role_id, secret_id and secret_id_accessor.

Output failure after issuance triggers bounded revocation. Exit 5 means a
mutation or credential cleanup is unconfirmed; inspect state before retrying.
Successful output files remain if writing the stdout report fails. Deleting a
role or SecretID prevents future logins; it does not revoke existing tokens.
Capabilities query physical API paths, not logical KV paths or other tokens.
`

type accessCommandOptions struct {
	network   networkOptions
	resource  string
	action    string
	name      string
	paths     []string
	file      string
	output    string
	force     bool
	appRole   vault.AppRoleOptions
	anonymous bool
}

// This prefix is shared with shell injection and override scanning. Flags
// belong after every command word, including identity's extra resource level.
func accessCommandPrefix(words []string) (resource, action string, depth int) {
	if len(words) < 2 {
		return "", "", 0
	}
	resource, action, depth = words[0], words[1], 2
	switch resource {
	case "policy":
		if action == "list" || action == "read" || action == "write" || action == "delete" {
			return
		}
	case "approle":
		switch action {
		case "list", "read", "write", "delete", "role-id", "credentials", "revoke-secret-id", "login":
			return
		}
	case "token":
		switch action {
		case "create", "revoke", "revoke-self", "capabilities":
			return
		}
	case "identity":
		if len(words) >= 3 && (action == "entity" || action == "group") {
			resource, action, depth = "identity "+action, words[2], 3
			if action == "list" || action == "read" || action == "write" || action == "delete" {
				return
			}
		}
	}
	return "", "", 0
}

func accessGroupHelp(words []string) bool {
	if len(words) == 1 {
		return true
	}
	if len(words) == 2 && (words[1] == "help" || words[1] == "-h" || words[1] == "--help") {
		return true
	}
	if words[0] == "identity" && (words[1] == "entity" || words[1] == "group") {
		return len(words) == 2 || (len(words) == 3 && (words[2] == "help" || words[2] == "-h" || words[2] == "--help"))
	}
	return false
}

func accessNeedsFile(resource, action string) bool {
	return action == "write" || (resource == "approle" && (action == "login" || action == "revoke-secret-id")) ||
		(resource == "token" && (action == "create" || action == "revoke"))
}

func accessNeedsOutput(resource, action string) bool {
	return (resource == "approle" && (action == "role-id" || action == "credentials" || action == "login")) ||
		(resource == "token" && action == "create")
}

func parseAccessCommandOptions(words []string) (accessCommandOptions, bool, error) {
	var options accessCommandOptions
	var depth int
	options.resource, options.action, depth = accessCommandPrefix(words)
	if depth == 0 {
		return options, false, errInvalidOptions
	}
	options.anonymous = options.resource == "approle" && options.action == "login"
	var address, namespace string
	var timeout time.Duration
	flags := flag.NewFlagSet("secretwright access", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&address, "address", "", "Vault URL")
	flags.StringVar(&namespace, "namespace", "", "Vault namespace")
	flags.DurationVar(&timeout, "timeout", 0, "operation timeout")
	if !options.anonymous {
		flags.StringVar(&options.network.tokenFile, "token-file", "", "operator token file")
	}
	if options.resource == "approle" {
		flags.StringVar(&options.appRole.Mount, "auth-mount", "approle", "existing AppRole auth mount")
	}
	if accessNeedsFile(options.resource, options.action) {
		flags.StringVar(&options.file, "file", "", "input file")
	}
	if accessNeedsOutput(options.resource, options.action) {
		flags.StringVar(&options.output, "out", "", "new private credential file")
	}
	if options.action == "delete" || (options.resource == "token" && (options.action == "revoke" || options.action == "revoke-self")) {
		flags.BoolVar(&options.force, "force", false, "confirm deletion or revocation")
	}
	if err := flags.Parse(words[depth:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return options, true, nil
		}
		return options, false, errInvalidOptions
	}
	invalid := false
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
		}
	})
	if accessNeedsFile(options.resource, options.action) {
		invalid = invalid || options.file == "" || options.file == "-"
	}
	if accessNeedsOutput(options.resource, options.action) {
		invalid = invalid || options.output == "" || options.output == "-"
	}
	if options.resource == "approle" && !validAccessMount(options.appRole.Mount) {
		invalid = true
	}
	if (options.action == "delete" || (options.resource == "token" && (options.action == "revoke" || options.action == "revoke-self"))) && !options.force {
		invalid = true
	}
	if invalid {
		return options, false, errInvalidOptions
	}
	paths := flags.Args()
	switch {
	case options.resource == "token" && options.action == "capabilities":
		var err error
		options.paths, err = vault.ValidateCapabilityPaths(paths)
		if err != nil {
			return options, false, errInvalidOptions
		}
	case options.action == "list" || options.resource == "token" || options.anonymous:
		if len(paths) != 0 {
			return options, false, errInvalidOptions
		}
	case strings.HasPrefix(options.resource, "identity "):
		if len(paths) > 1 || (options.action != "write" && len(paths) != 1) {
			return options, false, errInvalidOptions
		}
		if len(paths) == 1 {
			options.name = paths[0]
			if !validAccessIdentityID(options.name) {
				return options, false, errInvalidOptions
			}
		}
	default:
		if len(paths) != 1 || !validAccessCommandName(paths[0]) {
			return options, false, errInvalidOptions
		}
		options.name = paths[0]
	}
	if options.resource == "policy" && ((options.action == "write" || options.action == "delete") && strings.EqualFold(options.name, "root") || options.action == "delete" && strings.EqualFold(options.name, "default")) {
		return options, false, errInvalidOptions
	}
	return options, false, nil
}

func validAccessCommandName(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		character := value[i]
		if (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			continue
		}
		if i == 0 || (character != '_' && character != '-' && character != '.') {
			return false
		}
	}
	return true
}

func validAccessMount(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if !validAccessCommandName(segment) {
			return false
		}
	}
	return true
}

func validAccessIdentityID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, character := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if character != '-' {
				return false
			}
		} else if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

type accessCommandInput struct {
	policy      string
	role        vault.RoleSpec
	token       vault.TokenSpec
	entity      vault.EntitySpec
	group       vault.GroupSpec
	credentials vault.AppRoleCredentials
	targetToken string
}

func decodeAccessCommandInput(options accessCommandOptions) (accessCommandInput, error) {
	var input accessCommandInput
	if options.file == "" {
		return input, nil
	}
	if options.resource == "token" && options.action == "revoke" {
		value, err := vault.LoadToken(options.file)
		if err != nil {
			return input, errReadInput
		}
		input.targetToken = value
		return input, nil
	}
	file, err := os.Open(options.file)
	if err != nil {
		return input, errReadInput
	}
	defer file.Close()
	switch options.resource {
	case "policy":
		input.policy, err = vault.ReadPolicyInput(file)
	case "approle":
		if options.action == "write" {
			input.role, err = vault.DecodeRoleSpec(file)
		} else {
			input.credentials, err = vault.DecodeAppRoleCredentials(file)
			if err == nil && options.action == "revoke-secret-id" && input.credentials.SecretIDAccessor == "" {
				err = vault.ErrInvalidAccessInput
			}
		}
	case "token":
		input.token, err = vault.DecodeTokenSpec(file)
	case "identity entity":
		input.entity, err = vault.DecodeEntitySpec(file)
	case "identity group":
		input.group, err = vault.DecodeGroupSpec(file)
	default:
		err = errInvalidOptions
	}
	return input, err
}

func accessCommand(ctx context.Context, words []string, stdout, stderr io.Writer) int {
	if accessGroupHelp(words) {
		return writeUsage(stdout, stderr, accessUsage)
	}
	options, help, err := parseAccessCommandOptions(words)
	if help {
		return writeUsage(stdout, stderr, accessUsage)
	}
	if err != nil {
		return commandError(stderr, err)
	}
	input, err := decodeAccessCommandInput(options)
	if err != nil {
		return accessError(stderr, err)
	}
	client, err := vault.New(options.network.vault)
	if err != nil {
		return accessError(stderr, err)
	}
	var output *credentialOutput
	if options.output != "" {
		output, err = reserveCredentialOutput(options.output)
		if err != nil {
			return accessError(stderr, err)
		}
		defer output.abort()
	}
	operator := ""
	if !options.anonymous {
		operator, err = vault.LoadToken(options.network.tokenFile)
		if err != nil {
			return accessError(stderr, err)
		}
	}
	respond := func(value any, err error) int {
		if err != nil {
			return accessError(stderr, err)
		}
		return writeJSON(stdout, stderr, value)
	}
	switch options.resource {
	case "policy":
		switch options.action {
		case "list":
			return respond(client.ListPolicies(ctx, operator))
		case "read":
			return respond(client.ReadPolicy(ctx, operator, options.name))
		case "write":
			return respond(client.WritePolicy(ctx, operator, options.name, input.policy))
		case "delete":
			return respond(client.DeletePolicy(ctx, operator, options.name))
		}
	case "approle":
		switch options.action {
		case "list":
			return respond(client.ListAppRoles(ctx, operator, options.appRole))
		case "read":
			return respond(client.ReadAppRole(ctx, operator, options.name, options.appRole))
		case "write":
			return respond(client.WriteAppRole(ctx, operator, options.name, input.role, options.appRole))
		case "delete":
			return respond(client.DeleteAppRole(ctx, operator, options.name, options.appRole))
		case "revoke-secret-id":
			return respond(client.RevokeAppRoleSecretID(ctx, operator, options.name, input.credentials.SecretIDAccessor, options.appRole))
		case "role-id":
			roleID, err := client.ReadAppRoleID(ctx, operator, options.name, options.appRole)
			if err != nil {
				return accessError(stderr, err)
			}
			report := vault.CredentialReport{Kind: "role_id", Name: options.name, AuthMount: options.appRole.Mount}
			return commitAccessCredential(output, encodeCredentialLine(roleID), nil, report, stdout, stderr)
		case "credentials":
			credentials, err := client.IssueAppRoleCredentials(ctx, operator, options.name, options.appRole)
			if err != nil {
				return accessError(stderr, err)
			}
			encode := func(writer io.Writer) error { return vault.EncodeAppRoleCredentials(writer, credentials) }
			cleanup := func(ctx context.Context) error {
				_, err := client.RevokeAppRoleSecretID(ctx, operator, options.name, credentials.SecretIDAccessor, options.appRole)
				return err
			}
			return commitAccessCredential(output, encode, cleanup, credentials.Report, stdout, stderr)
		case "login":
			issued, err := client.LoginAppRole(ctx, input.credentials, options.appRole)
			if err != nil {
				return accessError(stderr, err)
			}
			cleanup := func(ctx context.Context) error {
				_, err := client.RevokeSelf(ctx, issued.Token)
				return err
			}
			return commitAccessCredential(output, encodeCredentialLine(issued.Token), cleanup, issued.Report, stdout, stderr)
		}
	case "token":
		switch options.action {
		case "create":
			issued, err := client.CreateToken(ctx, operator, input.token)
			if err != nil {
				return accessError(stderr, err)
			}
			cleanup := func(ctx context.Context) error {
				_, err := client.RevokeTokenAccessor(ctx, operator, issued.Accessor)
				return err
			}
			return commitAccessCredential(output, encodeCredentialLine(issued.Token), cleanup, issued.Report, stdout, stderr)
		case "revoke":
			return respond(client.RevokeToken(ctx, operator, input.targetToken))
		case "revoke-self":
			return respond(client.RevokeSelf(ctx, operator))
		case "capabilities":
			return respond(client.Capabilities(ctx, operator, options.paths))
		}
	case "identity entity":
		switch options.action {
		case "list":
			return respond(client.ListEntities(ctx, operator))
		case "read":
			return respond(client.ReadEntity(ctx, operator, options.name))
		case "write":
			return respond(client.WriteEntity(ctx, operator, options.name, input.entity))
		case "delete":
			return respond(client.DeleteEntity(ctx, operator, options.name))
		}
	case "identity group":
		switch options.action {
		case "list":
			return respond(client.ListGroups(ctx, operator))
		case "read":
			return respond(client.ReadGroup(ctx, operator, options.name))
		case "write":
			return respond(client.WriteGroup(ctx, operator, options.name, input.group))
		case "delete":
			return respond(client.DeleteGroup(ctx, operator, options.name))
		}
	}
	return commandError(stderr, errInvalidOptions)
}

func commitAccessCredential(output *credentialOutput, encode func(io.Writer) error, cleanup func(context.Context) error, report vault.CredentialReport, stdout, stderr io.Writer) int {
	if err := output.commit(encode); err != nil {
		output.abort()
		if cleanup != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := cleanup(ctx); err != nil {
				return accessError(stderr, vault.ErrAccessPartial)
			}
		}
		return accessError(stderr, errCredentialFile)
	}
	return writeJSON(stdout, stderr, report)
}

func accessError(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "secretwright:", err)
	switch {
	case errors.Is(err, vault.ErrAccessPartial), errors.Is(err, vault.ErrAccessUnconfirmed):
		return 5
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
