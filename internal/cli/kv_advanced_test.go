package cli_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func advancedFile(t *testing.T, body string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "private-input-marker.json")
	if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
		t.Fatal("could not prepare private advanced input")
	}
	return name
}

func advancedServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("X-Vault-Token") != "advanced-private-token" {
			t.Error("advanced operation lost selected credentials")
		}
		switch {
		case r.URL.Path == "/v1/secret/metadata/app" && r.URL.Query().Get("list") == "true":
			kvWriteData(t, w, map[string]any{"keys": []string{"b", "a"}})
		case r.URL.Path == "/v1/secret/data/app/a":
			kvWriteData(t, w, map[string]any{"data": map[string]any{"value": "private-data-marker", "number": 1}, "metadata": map[string]any{"version": 3}})
		case r.URL.Path == "/v1/secret/data/app/b":
			kvWriteData(t, w, map[string]any{"data": map[string]any{"other": true}, "metadata": map[string]any{"version": 2}})
		default:
			t.Error("advanced operation made an unexpected request")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server, &requests
}

func TestAdvancedCommandHelpIsOfflineAndDoesNotConsumeInput(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address-marker")
	for _, command := range []string{"tree", "find", "replace", "cptree", "rmtree", "backup", "restore"} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, command, "--help")
		if code != 0 || !strings.Contains(output, "Usage:") || diagnostics != "" {
			t.Errorf("%s help failed: exit=%d", command, code)
		}
	}
}

func TestAdvancedRejectsInvalidOptionsWithoutReadingInputOrNetworking(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "private-token-marker")
	for _, args := range [][]string{
		{"tree", "--concurrency", "0"},
		{"tree", "--concurrency", "17"},
		{"tree", "--mount", "secret"},
		{"tree", "/private?path-marker"},
		{"tree", "--force"},
		{"find", "/secret/app"},
		{"find", "--file", "-", "/secret/app"},
		{"replace", "--file", "-", "/secret/app"},
		{"backup", "--file", "-", "/secret/app"},
		{"restore", "--file", "-", "/secret/app"},
		{"cptree", "/secret/app"},
		{"rmtree"},
		{"restore", "--file", "private-missing-marker"},
	} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") {
			t.Errorf("invalid advanced options produced unsafe output: command=%s exit=%d", args[0], code)
		}
	}
	if requests.Load() != 0 {
		t.Error("invalid advanced options contacted Vault")
	}
}

func TestAdvancedFilesAreDecodedBeforeCredentialsAndNetworking(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	for _, test := range []struct {
		command string
		body    string
	}{
		{command: "find", body: `{"value":"private-json-marker"} {}`},
		{command: "replace", body: `{"match":{"value":"private-json-marker"},"replacement":{"value":"new"},"unexpected":true}`},
		{command: "replace", body: `{"match":{"x":1,"x":2},"replacement":{"x":3}}`},
		{command: "restore", body: `{"format":"secretwright-kv","version":1,"root":"/secret","entries":[{"path":"../private-archive-marker","data":{"value":1}}]}`},
	} {
		name := advancedFile(t, test.body)
		args := []string{test.command, "--file", name, "--token-file", filepath.Join(t.TempDir(), "missing-token"), "/secret/app"}
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "token file") || strings.Contains(diagnostics, "private-") {
			t.Errorf("invalid %s file was not validated safely before credentials", test.command)
		}
	}
	if requests.Load() != 0 {
		t.Error("invalid advanced input contacted Vault")
	}
}

func TestAdvancedTreeAndFindReturnNamesWithoutData(t *testing.T) {
	cleanEnvironment(t)
	server, requests := advancedServer(t)
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "advanced-private-token")
	base := []string{"--mount", "secret", "--kv-version", "2"}
	args := append([]string{"tree"}, base...)
	args = append(args, "/secret/app")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
	if code != 0 || diagnostics != "" {
		t.Fatalf("tree failed: exit=%d diagnostics=%q", code, diagnostics)
	}
	kvAssertJSON(t, output, `{"root":"/secret/app","entries":[{"path":"/secret/app/a","directory":false},{"path":"/secret/app/b","directory":false}]}`)
	if requests.Load() != 1 {
		t.Error("tree read secret values or repeated its listing")
	}
	match := advancedFile(t, `{"number":1.0,"value":"private-data-marker"}`)
	args = append([]string{"find", "--file", match}, base...)
	args = append(args, "/secret/app")
	code, output, diagnostics = runWriteCLI(f03PanicReader{}, args...)
	if code != 0 || diagnostics != "" {
		t.Fatalf("find failed: exit=%d diagnostics=%q", code, diagnostics)
	}
	kvAssertJSON(t, output, `["/secret/app/a"]`)
	if strings.Contains(output+diagnostics, "private-") {
		t.Error("find printed query data or credentials")
	}
}

func TestAdvancedBackupPublishesPrivateArchiveAndNeverClobbers(t *testing.T) {
	cleanEnvironment(t)
	server, _ := advancedServer(t)
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "advanced-private-token")
	directory := t.TempDir()
	name := filepath.Join(directory, "private-backup-marker.json")
	args := []string{"backup", "--file", name, "--mount", "secret", "--kv-version", "2", "/secret/app"}
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
	if code != 0 || diagnostics != "" {
		t.Fatalf("backup failed: exit=%d diagnostics=%q", code, diagnostics)
	}
	kvAssertJSON(t, output, `{"root":"/secret/app","entries":2}`)
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("backup did not publish a private file")
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal("could not open private archive")
	}
	archive, err := vault.DecodeArchive(file)
	file.Close()
	if err != nil || len(archive.Entries) != 2 || archive.Entries[0].Path != "a" || archive.Entries[0].Data["value"] != "private-data-marker" {
		t.Fatal("backup file did not preserve source snapshots")
	}
	before, err := os.ReadFile(name)
	if err != nil {
		t.Fatal("could not inspect private archive")
	}
	code, output, diagnostics = runWriteCLI(f03PanicReader{}, args...)
	after, readErr := os.ReadFile(name)
	if code != 1 || output != "" || diagnostics == "" || readErr != nil || !reflect.DeepEqual(before, after) {
		t.Error("backup clobbered an existing archive")
	}
	link := filepath.Join(directory, "private-link-marker.json")
	if err := os.Symlink(name, link); err != nil {
		t.Fatal("could not prepare archive symlink")
	}
	args[2] = link
	code, output, diagnostics = runWriteCLI(f03PanicReader{}, args...)
	after, readErr = os.ReadFile(name)
	if code != 1 || output != "" || diagnostics == "" || readErr != nil || !reflect.DeepEqual(before, after) {
		t.Error("backup followed or replaced an archive symlink")
	}
	files, err := os.ReadDir(directory)
	if err != nil || len(files) != 2 {
		t.Error("backup left a temporary secret file")
	}
}

func TestAdvancedRestoreUsesWholeArchiveAndPrintsMetadata(t *testing.T) {
	cleanEnvironment(t)
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		if r.URL.Path != "/v1/secret/data/restored/a" || (r.Method != http.MethodPost && r.Method != http.MethodPut) {
			t.Error("restore used a wrong destination or operation")
		}
		var body struct {
			Data    map[string]any `json:"data"`
			Options struct {
				CAS int `json:"cas"`
			} `json:"options"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber()
		if err := decoder.Decode(&body); err != nil || body.Options.CAS != 0 || body.Data["value"] != "private-restore-marker" {
			t.Error("restore lost data or create-only CAS")
		}
		kvWriteData(t, w, map[string]any{"version": 1})
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "advanced-private-token")
	name := advancedFile(t, `{"format":"secretwright-kv","version":1,"root":"/source","entries":[{"path":"a","data":{"value":"private-restore-marker"}}]}`)
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "restore", "--file", name, "--mount", "secret", "--kv-version", "2", "/secret/restored")
	if code != 0 || diagnostics != "" || writes.Load() != 1 || strings.Contains(output+diagnostics, "private-") {
		t.Errorf("restore output or execution failed: exit=%d", code)
	}
	var report vault.BulkResult
	if err := json.Unmarshal([]byte(output), &report); err != nil || len(report.Items) != 1 || report.Items[0].Status != "written" {
		t.Error("restore did not print a complete metadata report")
	}
}

func TestAdvancedRestoreReportsConfirmedPartialChanges(t *testing.T) {
	cleanEnvironment(t)
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		switch r.URL.Path {
		case "/v1/secret/data/restored/a":
			kvWriteData(t, w, map[string]any{"version": 1})
		case "/v1/secret/data/restored/b":
			w.WriteHeader(http.StatusForbidden)
		default:
			t.Error("partial restore dispatched work after a failure")
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "advanced-private-token")
	name := advancedFile(t, `{"format":"secretwright-kv","version":1,"root":"/source","entries":[{"path":"a","data":{"value":1}},{"path":"b","data":{"value":2}},{"path":"c","data":{"value":3}}]}`)
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "restore", "--concurrency", "1", "--file", name, "--mount", "secret", "--kv-version", "2", "/secret/restored")
	var report vault.BulkResult
	if code != 5 || diagnostics == "" || writes.Load() != 2 || json.Unmarshal([]byte(output), &report) != nil || len(report.Items) != 3 {
		t.Fatal("partial restore did not report confirmed changes and unstarted items")
	}
	statuses := []string{report.Items[0].Status, report.Items[1].Status, report.Items[2].Status}
	if !reflect.DeepEqual(statuses, []string{"written", "failed", "not_started"}) || strings.Contains(output+diagnostics, "advanced-private-token") {
		t.Error("partial restore lost ordered statuses or exposed its credential")
	}
}

func TestAdvancedBackupReadFailurePublishesNoFile(t *testing.T) {
	cleanEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/metadata/app") {
			kvWriteData(t, w, map[string]any{"keys": []string{"a"}})
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "advanced-private-token")
	directory := t.TempDir()
	name := filepath.Join(directory, "backup.json")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "backup", "--file", name, "--mount", "secret", "--kv-version", "2", "/secret/app")
	files, err := os.ReadDir(directory)
	if code != 2 || output != "" || diagnostics == "" || err != nil || len(files) != 0 {
		t.Error("failed backup published an incomplete archive or private temporary file")
	}
}

func TestShellAdvancedCommandsPreserveStartupConfigurationAndHistory(t *testing.T) {
	cleanEnvironment(t)
	server, _ := advancedServer(t)
	defer server.Close()
	t.Setenv("VAULT_ADDR", "https://invalid.example")
	t.Setenv("VAULT_TOKEN", "advanced-private-token")
	input := "tree --mount secret --kv-version 2\nhistory\n"
	code, output, diagnostics := runShellCLI(strings.NewReader(input), "shell", "--no-prompt", "--address", server.URL, "--cwd", "/secret/app")
	if code != 0 || diagnostics != "" {
		t.Fatalf("advanced shell lost fixed configuration: exit=%d diagnostics=%q", code, diagnostics)
	}
	values := decodeShellOutputs(t, output)
	if len(values) != 2 || !reflect.DeepEqual(values[1], []any{}) {
		t.Error("advanced command with options entered shell history")
	}
	for _, line := range []string{
		"replace --dry-run --address https://private-override-marker /secret/app\n",
		"replace --file - /secret/app\n",
		"restore --file - /secret/app\n",
	} {
		code, output, diagnostics = runShellCLI(strings.NewReader(line+"pwd\n"), "shell", "--no-prompt")
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") {
			t.Error("advanced shell accepted a connection override or consumed commands as data")
		}
	}
}
