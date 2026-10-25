package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/cli"
)

const templateCLIManifest = `api_version: secretwright/architecture/v1
name: example
instances:
  - id: app
    template: single-app
    mount: example
    applications: [api]
`

func templateCLIInput(t *testing.T, body string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "private-architecture-input.yaml")
	if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
		t.Fatal("could not prepare architecture input")
	}
	return name
}

func TestTemplateCatalogExamplesAndRenderingIgnoreCredentialsAndNetwork(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CACERT", filepath.Join(t.TempDir(), "private-missing-ca"))
	t.Setenv("VAULT_TOKEN", "private-template-operator")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "template", "list")
	var catalog []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if code != 0 || diagnostics != "" || json.Unmarshal([]byte(output), &catalog) != nil {
		t.Fatal("offline template catalog did not produce JSON")
	}
	var names []string
	for _, entry := range catalog {
		if entry.Description == "" {
			t.Error("template catalog omitted its description")
		}
		names = append(names, entry.Name)
	}
	if !reflect.DeepEqual(names, []string{"multi-app", "multi-env", "multi-user", "saas", "single-app", "single-user"}) {
		t.Fatal("template catalog lost one of its six architecture patterns or stable order")
	}
	for _, name := range names {
		code, example, diagnostics := runWriteCLI(f03PanicReader{}, "template", "show", name)
		var manifest map[string]any
		if code != 0 || diagnostics != "" || json.Unmarshal([]byte(example), &manifest) != nil || manifest["api_version"] != "secretwright/architecture/v1" {
			t.Fatal("template show did not produce an offline editable manifest")
		}
		code, rendered, diagnostics := runWriteCLI(f03PanicReader{}, "template", "render", "--file", templateCLIInput(t, example))
		document, err := blueprint.Load(strings.NewReader(rendered), nil)
		if code != 0 || diagnostics != "" || err != nil || len(document.Resources) == 0 || strings.Contains(rendered, "private-") {
			t.Error("catalog example did not render a complete usable blueprint offline")
		}
	}
	code, output, diagnostics = runWriteCLI(f03PanicReader{}, "template", "schema")
	var schema map[string]any
	if code != 0 || diagnostics != "" || json.Unmarshal([]byte(output), &schema) != nil || schema["$id"] != "urn:secretwright:architecture:v1" {
		t.Error("architecture schema was not available offline")
	}
}

func TestTemplateHelpDoesNotReadFilesInputOrConnectionConfiguration(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CACERT", "/private-missing-ca")
	for _, args := range [][]string{
		{"template"}, {"template", "help"}, {"template", "--help"},
		{"template", "list", "--help"}, {"template", "show", "--help"},
		{"template", "schema", "--help"}, {"template", "render", "--help"},
	} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 0 || diagnostics != "" || !strings.Contains(output, "Usage:") {
			t.Error("template help required an input file or network configuration")
		}
	}
}

func TestTemplateRejectsUnusedOptionsAndInvalidFilesWithoutAnyHTTP(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-template-operator")
	valid := templateCLIInput(t, templateCLIManifest)
	invalid := templateCLIInput(t, "name: private-invalid-template\ninstances: [private-input]\n")
	missing := filepath.Join(t.TempDir(), "private-missing-input")
	for _, args := range [][]string{
		{"template", "delete"}, {"template", "show"}, {"template", "show", "private-unknown-template"},
		{"template", "show", "single-app", "extra"}, {"template", "list", "extra"},
		{"template", "schema", "--file", valid}, {"template", "list", "--address", server.URL},
		{"template", "show", "--token-file", missing, "single-app"},
		{"template", "render"}, {"template", "render", "--file", "-"},
		{"template", "render", "--file", ""}, {"template", "render", "--file", valid, "extra"},
		{"template", "render", "--file", valid, "--vars", invalid},
		{"template", "render", "--file", valid, "--namespace", "private-namespace"},
		{"template", "render", "--file", valid, "--cwd", "/private-cwd"},
		{"template", "render", "--file", missing}, {"template", "render", "--file", invalid},
		{"template", "render", "--file", t.TempDir()},
	} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") {
			t.Error("invalid template command was not rejected before output or exposed its input")
		}
	}
	if requests.Load() != 0 {
		t.Error("offline template command contacted Vault")
	}
}

func TestTemplateRenderKeepsTheBlueprintSpecsAndDeterministicOutput(t *testing.T) {
	cleanEnvironment(t)
	name := templateCLIInput(t, templateCLIManifest)
	code, first, diagnostics := runWriteCLI(f03PanicReader{}, "template", "render", "--file", name)
	if code != 0 || diagnostics != "" || !strings.HasSuffix(first, "\n") {
		t.Fatal("template render did not emit a complete JSON document")
	}
	code, second, diagnostics := runWriteCLI(f03PanicReader{}, "template", "render", "--file", name)
	if code != 0 || diagnostics != "" || first != second {
		t.Error("identical template input changed its rendered bytes")
	}
	document, err := blueprint.Load(strings.NewReader(first), nil)
	if err != nil || document.Name != "example" || len(document.Resources) != 3 {
		t.Fatal("rendered single-app architecture was not a complete three-resource blueprint")
	}
	for _, resource := range document.Resources {
		if len(resource.Spec) == 0 {
			t.Error("rendered blueprint lost its configuration due to metadata-only JSON tags")
		}
	}
}

func TestTemplateCommandsRejectOutputFailuresAndShortWrites(t *testing.T) {
	name := templateCLIInput(t, templateCLIManifest)
	for _, args := range [][]string{
		{"template", "list"}, {"template", "show", "single-app"},
		{"template", "schema"}, {"template", "render", "--file", name},
	} {
		for _, writer := range []io.Writer{failedWriter{}, blueprintShortWriter{}} {
			var diagnostics bytes.Buffer
			code := cli.RunWithInput(context.Background(), args, f03PanicReader{}, writer, &diagnostics, "test")
			if code != 1 || diagnostics.Len() == 0 || strings.Contains(diagnostics.String(), "private-") {
				t.Error("template command reported success after a failed or truncated output")
			}
		}
	}
}

func TestShellTemplateCommandsRemainOfflineAndOutsideHistory(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CACERT", "/private-missing-ca")
	name := templateCLIInput(t, templateCLIManifest)
	commands := "template list\ntemplate show single-app\ntemplate schema\ntemplate render --file " + name + "\nhistory\n"
	code, output, diagnostics := runShellCLI(strings.NewReader(commands), "shell", "--no-prompt", "--address", "private-invalid-startup-address", "--token-file", "/private-unreadable-token", "--cwd", "/unused-kv-cwd")
	values := decodeShellOutputs(t, output)
	if code != 0 || diagnostics != "" || len(values) != 5 || !reflect.DeepEqual(values[4], []any{}) {
		t.Error("shell template commands inherited connection credentials, KV cwd or history")
	}
	for _, line := range []string{
		"template render --file " + name + " --address https://private-override",
		"template render --token-file /private-token --file " + name,
		"template render --file -", "template show single-app --namespace private-team",
	} {
		code, output, diagnostics = runShellCLI(strings.NewReader(line+"\npwd\n"), "shell", "--no-prompt")
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") {
			t.Error("shell accepted template connection options or consumed a command as input")
		}
	}
}
