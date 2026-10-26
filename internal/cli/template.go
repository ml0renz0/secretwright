package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"

	"github.com/ml0renz0/secretwright/internal/architecture"
	"github.com/ml0renz0/secretwright/internal/fileformat"
)

const templateUsage = `Usage: secretwright template ACTION [options]

  list                        List the six architecture patterns as JSON
  show [--format yaml|json] NAME
                              Print an editable architecture manifest
  schema                      Export the embedded architecture JSON Schema
  render --file ARCHITECTURE [--format yaml|json]
                              Render a complete F07 blueprint

Show and render default to YAML. Use --format json to select JSON. Catalog and
schema output remain JSON. Show options must precede NAME.

Every template command runs offline. Files must be actual filenames, never '-'
or stdin. Connection, token, namespace, working-directory and variable options
are not accepted. Rendering does not issue credentials or apply resources.

Save the rendered configuration to a file and use blueprint validate/plan/apply
to review and create it. The output intentionally contains ACLs and resource
configuration. User entities need an external authentication alias binding;
application templates require an existing AppRole auth mount at plan/apply.
`

var errReadArchitecture = errors.New("could not read the architecture file")

type templateCommandOptions struct {
	action string
	name   string
	file   string
	format fileformat.Format
}

// Every recognized template action is offline. Shell override detection shares
// the command depth without injecting its connection or loading credentials.
func templateCommandPrefix(words []string) (string, int) {
	if len(words) < 2 || words[0] != "template" {
		return "", 0
	}
	switch words[1] {
	case "list", "show", "schema", "render":
		return words[1], 2
	default:
		return "", 0
	}
}

func parseTemplateCommandOptions(words []string) (templateCommandOptions, bool, error) {
	var options templateCommandOptions
	var depth int
	options.action, depth = templateCommandPrefix(words)
	if depth == 0 {
		return options, false, errInvalidOptions
	}
	flags := flag.NewFlagSet("secretwright template", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var format string
	if options.action == "show" || options.action == "render" {
		flags.StringVar(&format, "format", "", "output format: yaml or json")
	}
	if options.action == "render" {
		flags.StringVar(&options.file, "file", "", "architecture file")
	}
	if err := flags.Parse(words[depth:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return options, true, nil
		}
		return options, false, errInvalidOptions
	}
	if options.action == "show" {
		if flags.NArg() != 1 || flags.Arg(0) == "" {
			return options, false, errInvalidOptions
		}
		options.name = flags.Arg(0)
	} else if flags.NArg() != 0 {
		return options, false, errInvalidOptions
	}
	if options.action == "render" && (options.file == "" || options.file == "-") {
		return options, false, errInvalidOptions
	}
	if options.action == "show" || options.action == "render" {
		var err error
		options.format, err = fileformat.Parse(format)
		if err != nil {
			return options, false, errInvalidOptions
		}
	}
	return options, false, nil
}

func templateCommand(words []string, stdout, stderr io.Writer) int {
	if len(words) == 1 || len(words) == 2 && (words[1] == "help" || words[1] == "-h" || words[1] == "--help") {
		return writeUsage(stdout, stderr, templateUsage)
	}
	options, help, err := parseTemplateCommandOptions(words)
	if help {
		return writeUsage(stdout, stderr, templateUsage)
	}
	if err != nil {
		return commandError(stderr, err)
	}
	var body []byte
	switch options.action {
	case "list":
		body, err = json.MarshalIndent(architecture.Catalog(), "", "  ")
		if err != nil {
			return commandError(stderr, errors.New("could not encode the template catalog"))
		}
		body = append(body, '\n')
	case "schema":
		body = architecture.Schema()
	case "show":
		body, err = architecture.Example(options.name)
	case "render":
		file, openErr := os.Open(options.file)
		if openErr != nil {
			return commandError(stderr, errReadArchitecture)
		}
		defer file.Close()
		body, err = architecture.Render(file)
	}
	if err != nil {
		return commandError(stderr, architecture.ErrInvalidTemplate)
	}
	if options.action == "show" || options.action == "render" {
		body, err = fileformat.EncodeJSON(body, options.format)
		if err != nil {
			return commandError(stderr, fileformat.ErrInvalidFormat)
		}
	}
	written, err := stdout.Write(body)
	if err != nil || written != len(body) {
		return commandError(stderr, errors.New("could not write template output"))
	}
	return 0
}
