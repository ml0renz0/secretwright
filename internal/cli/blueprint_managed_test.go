package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/cli"
)

type managedCLIVault struct {
	server   *httptest.Server
	mu       sync.Mutex
	policy   string
	requests atomic.Int32
	writes   atomic.Int32
}

func newManagedCLIVault(t *testing.T, existing bool) *managedCLIVault {
	t.Helper()
	fixture := &managedCLIVault{}
	if existing {
		fixture.policy = blueprintCLIPolicy
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.requests.Add(1)
		if r.URL.Path == "/v1/sys/health" {
			if r.Method != http.MethodGet || r.Header.Get("X-Vault-Token") != "" {
				t.Error("state target binding sent a credential or mutated health")
			}
			accessReply(t, w, map[string]any{"initialized": true, "sealed": false, "standby": false, "version": "2.2.0", "cluster_id": "11111111-1111-4111-8111-111111111111"})
			return
		}
		if r.URL.Path != "/v1/sys/policies/acl/app" || r.Header.Get("X-Vault-Token") != "private-managed-cli-token" || r.Header.Get("X-Vault-Namespace") != "team" {
			t.Error("managed blueprint changed its endpoint, namespace or selected credential")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		if r.Method == http.MethodGet {
			if fixture.policy == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			accessReply(t, w, map[string]any{"data": map[string]any{"policy": fixture.policy}})
			return
		}
		fixture.writes.Add(1)
		if r.Method != http.MethodPost {
			t.Error("managed blueprint used an unsupported mutation")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Policy string `json:"policy"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Policy == "" {
			t.Error("managed blueprint lost its desired ACL")
		}
		fixture.policy = body.Policy
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (fixture *managedCLIVault) replacePolicy(policy string) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.policy = policy
}

func managedCLIArguments(action, blueprintFile, stateFile string, extra ...string) []string {
	arguments := []string{"blueprint", action, "--file", blueprintFile, "--state", stateFile}
	return append(arguments, extra...)
}

func managedCLIState(t *testing.T, path string) ([]byte, map[string]any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("managed command did not leave its private state")
	}
	var state map[string]any
	if json.Unmarshal(body, &state) != nil {
		t.Fatal("managed command wrote an incomplete state checkpoint")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("managed inventory was not a private regular file")
	}
	if strings.Contains(string(body), "private-") || strings.Contains(string(body), `"spec"`) || strings.Contains(string(body), `"policy"`+":") {
		t.Error("managed inventory retained configuration or credentials")
	}
	return body, state
}

func TestManagedBlueprintCLIAdoptsExplicitlyBlocksDriftAndRepairsItsOwnACL(t *testing.T) {
	cleanEnvironment(t)
	fixture := newManagedCLIVault(t, true)
	t.Setenv("VAULT_ADDR", fixture.server.URL)
	t.Setenv("VAULT_NAMESPACE", "team")
	t.Setenv("VAULT_TOKEN", "private-managed-cli-token")
	blueprintFile := blueprintCLIDocument(t, "app")
	stateFile := filepath.Join(t.TempDir(), "ownership.json")
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, managedCLIArguments("adopt", blueprintFile, stateFile)...)
	if code != 0 || diagnostics != "" || output == "" || fixture.writes.Load() != 0 || strings.Contains(output, "private-") {
		t.Fatal("explicit adoption did not remain read-only and private")
	}
	before, state := managedCLIState(t, stateFile)
	if state["api_version"] != "secretwright/state/v1" || state["blueprint"] != "test-blueprint" || len(state["resources"].([]any)) != 1 {
		t.Fatal("adoption did not capture the equivalent resource and blueprint binding")
	}
	for _, action := range []string{"plan", "apply"} {
		code, output, diagnostics = runWriteCLI(f03PanicReader{}, managedCLIArguments(action, blueprintFile, stateFile)...)
		if code != 0 || diagnostics != "" || fixture.writes.Load() != 0 || strings.Contains(output, "private-") {
			t.Error("equivalent managed resource caused a mutation or exposed configuration")
		}
		if action == "plan" && !reflect.DeepEqual(blueprintCLIReport(t, output)["changes"], []any{}) {
			t.Error("adopted matching resource did not produce an empty plan")
		}
		after, _ := managedCLIState(t, stateFile)
		if !bytes.Equal(before, after) {
			t.Error("a managed noop changed its baseline or revision")
		}
		if _, err := os.Lstat(stateFile + ".lock"); !os.IsNotExist(err) {
			t.Error("managed command left a lock after returning")
		}
	}
	lockFile := stateFile + ".lock"
	if os.WriteFile(lockFile, []byte("private-other-operation"), 0o600) != nil {
		t.Fatal("could not prepare a concurrent writer's lock")
	}
	code, _, diagnostics = runWriteCLI(f03PanicReader{}, managedCLIArguments("plan", blueprintFile, stateFile)...)
	if code != 0 || diagnostics != "" {
		t.Error("read-only managed plan attempted to take a writer lock")
	}
	if body, err := os.ReadFile(lockFile); err != nil || string(body) != "private-other-operation" {
		t.Error("read-only managed plan changed another operation's lock")
	}
	if os.Remove(lockFile) != nil {
		t.Fatal("could not release the test's writer lock")
	}
	t.Setenv("VAULT_NAMESPACE", "other-team")
	code, output, diagnostics = runWriteCLI(f03PanicReader{}, managedCLIArguments("apply", blueprintFile, stateFile)...)
	if code != 4 || output != "" || diagnostics == "" || fixture.writes.Load() != 0 || strings.Contains(diagnostics, "private-") {
		t.Error("managed inventory was reused in a different namespace")
	}
	if after, _ := managedCLIState(t, stateFile); !bytes.Equal(before, after) {
		t.Error("rejected target binding changed the inventory")
	}
	t.Setenv("VAULT_NAMESPACE", "team")
	fixture.replacePolicy(`path "private-external-change/*" { capabilities = ["deny"] }`)
	for _, action := range []string{"plan", "apply"} {
		code, output, diagnostics = runWriteCLI(f03PanicReader{}, managedCLIArguments(action, blueprintFile, stateFile)...)
		if code != 4 || output == "" || diagnostics == "" || fixture.writes.Load() != 0 || strings.Contains(output+diagnostics, "private-") {
			t.Error("external drift was not reported privately before any write")
		}
		after, _ := managedCLIState(t, stateFile)
		if !bytes.Equal(before, after) {
			t.Error("blocked drift altered the managed inventory")
		}
	}
	code, output, diagnostics = runWriteCLI(f03PanicReader{}, managedCLIArguments("apply", blueprintFile, stateFile, "--repair")...)
	if code != 0 || diagnostics != "" || fixture.writes.Load() != 1 || strings.Contains(output, "private-") {
		t.Fatal("explicit repair did not make exactly one owned ACL update")
	}
	after, _ := managedCLIState(t, stateFile)
	if bytes.Equal(before, after) {
		t.Error("confirmed repair did not advance its durable checkpoint")
	}
	code, output, diagnostics = runWriteCLI(f03PanicReader{}, managedCLIArguments("plan", blueprintFile, stateFile)...)
	if code != 0 || diagnostics != "" || !reflect.DeepEqual(blueprintCLIReport(t, output)["changes"], []any{}) || fixture.writes.Load() != 1 {
		t.Error("repaired resource did not converge to a read-only empty plan")
	}
	code, output, diagnostics = runWriteCLI(f03PanicReader{}, managedCLIArguments("adopt", blueprintFile, stateFile)...)
	if code == 0 || output != "" || diagnostics == "" {
		t.Error("adoption overwrote an existing inventory")
	}
	final, _ := managedCLIState(t, stateFile)
	if !bytes.Equal(after, final) {
		t.Error("rejected adoption changed an existing inventory")
	}
}

func TestManagedBlueprintRejectsInvalidStateAndLocksBeforeCredentials(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CACERT", "/private-missing-ca")
	blueprintFile := blueprintCLIDocument(t, "app")
	missingToken := filepath.Join(t.TempDir(), "private-missing-token")
	invalidState := filepath.Join(t.TempDir(), "private-invalid-state")
	if os.WriteFile(invalidState, []byte(`{"private-marker":"private-value"}`), 0o600) != nil {
		t.Fatal("could not prepare the invalid private inventory")
	}
	for _, action := range []string{"plan", "apply", "recover"} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, managedCLIArguments(action, blueprintFile, invalidState, "--token-file", missingToken)...)
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") || strings.Contains(diagnostics, "token file") {
			t.Error("invalid local state was not rejected before credential or connection inspection")
		}
		if _, err := os.Lstat(invalidState + ".lock"); !os.IsNotExist(err) {
			t.Error("failed state validation retained a lock artifact")
		}
	}
	lock := invalidState + ".lock"
	if os.WriteFile(lock, []byte("private-existing-lock"), 0o600) != nil {
		t.Fatal("could not prepare the existing state lock")
	}
	for _, action := range []string{"apply", "recover"} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, managedCLIArguments(action, blueprintFile, invalidState, "--token-file", missingToken)...)
		if code != 4 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") || strings.Contains(diagnostics, "token file") {
			t.Error("existing state lock did not stop the operation before credential I/O")
		}
		if body, err := os.ReadFile(lock); err != nil || string(body) != "private-existing-lock" {
			t.Error("a failed lock attempt removed or changed another operation's lock")
		}
	}
}

func TestManagedBlueprintFlagsAndHelpRemainStrictAndOffline(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_TOKEN", "private-inherited-token")
	for _, action := range []string{"adopt", "recover"} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, "blueprint", action, "--help")
		if code != 0 || !strings.Contains(output, "Usage:") || diagnostics != "" {
			t.Error("managed help selected credentials or opened its state")
		}
	}
	blueprintFile := blueprintCLIDocument(t, "app")
	stateFile := filepath.Join(t.TempDir(), "state.json")
	for _, arguments := range [][]string{
		{"blueprint", "adopt", "--file", blueprintFile},
		{"blueprint", "recover", "--file", blueprintFile},
		{"blueprint", "plan", "--file", blueprintFile, "--repair"},
		{"blueprint", "apply", "--file", blueprintFile, "--repair"},
		managedCLIArguments("adopt", blueprintFile, stateFile, "--repair"),
		managedCLIArguments("recover", blueprintFile, stateFile, "--repair"),
		managedCLIArguments("plan", blueprintFile, stateFile, "--adopt-pending"),
		managedCLIArguments("apply", blueprintFile, stateFile, "--adopt-pending"),
		managedCLIArguments("adopt", blueprintFile, stateFile, "--adopt-pending"),
		managedCLIArguments("plan", blueprintFile, "-"),
		managedCLIArguments("apply", blueprintFile, "-"),
		managedCLIArguments("adopt", "-", stateFile),
		managedCLIArguments("recover", "-", stateFile),
		managedCLIArguments("apply", blueprintFile, stateFile, "unexpected"),
		{"blueprint", "schema", "--state", stateFile},
		{"blueprint", "validate", "--file", blueprintFile, "--state", stateFile},
	} {
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, arguments...)
		if code != 1 || output != "" || diagnostics == "" || strings.Contains(diagnostics, "private-") {
			t.Error("managed command accepted an unsafe combination or echoed its rejected input")
		}
	}
}

func TestManagedBlueprintRecoveryRequiresExplicitAdoptionOfUncertainCreation(t *testing.T) {
	cleanEnvironment(t)
	fixture := newManagedCLIVault(t, false)
	t.Setenv("VAULT_ADDR", fixture.server.URL)
	t.Setenv("VAULT_NAMESPACE", "team")
	t.Setenv("VAULT_TOKEN", "private-managed-cli-token")
	blueprintFile := blueprintCLIDocument(t, "app")
	stateFile := filepath.Join(t.TempDir(), "state.json")
	code, _, diagnostics := runWriteCLI(f03PanicReader{}, managedCLIArguments("adopt", blueprintFile, stateFile)...)
	if code != 0 || diagnostics != "" {
		t.Fatal("clean target could not initialize an empty managed inventory")
	}
	_, state := managedCLIState(t, stateFile)
	state["resources"] = []any{map[string]any{"id": "app", "kind": "policy", "name": "app", "pending": "create"}}
	pending, err := json.Marshal(state)
	if err != nil || os.WriteFile(stateFile, pending, 0o600) != nil {
		t.Fatal("could not prepare the uncertain creation checkpoint")
	}
	fixture.replacePolicy(blueprintCLIPolicy)
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, managedCLIArguments("recover", blueprintFile, stateFile)...)
	if code != 4 || diagnostics == "" || fixture.writes.Load() != 0 || strings.Contains(output+diagnostics, "private-") {
		t.Error("recovery silently claimed an uncertain concurrent creation")
	}
	after, _ := managedCLIState(t, stateFile)
	if !bytes.Equal(pending, after) {
		t.Error("rejected recovery changed the pending checkpoint")
	}
	code, output, diagnostics = runWriteCLI(f03PanicReader{}, managedCLIArguments("recover", blueprintFile, stateFile, "--adopt-pending")...)
	if code != 0 || diagnostics != "" || output == "" || fixture.writes.Load() != 0 || strings.Contains(output, "private-") {
		t.Error("explicit recovery did not remain read-only against Vault")
	}
	_, recovered := managedCLIState(t, stateFile)
	resources := recovered["resources"].([]any)
	if len(resources) != 1 || resources[0].(map[string]any)["pending"] != nil {
		t.Error("confirmed recovery did not clear the pending creation")
	}
	var diagnostic bytes.Buffer
	code = cli.RunWithInput(context.Background(), managedCLIArguments("plan", blueprintFile, stateFile), f03PanicReader{}, failedWriter{}, &diagnostic, "test")
	if code != 1 || diagnostic.Len() == 0 || fixture.writes.Load() != 0 || strings.Contains(diagnostic.String(), "private-") {
		t.Error("managed read-only plan hid a failed output or exposed internal values")
	}
	diagnostic.Reset()
	code = cli.RunWithInput(context.Background(), managedCLIArguments("plan", blueprintFile, stateFile), f03PanicReader{}, blueprintShortWriter{}, &diagnostic, "test")
	if code != 1 || diagnostic.Len() == 0 || fixture.writes.Load() != 0 || strings.Contains(diagnostic.String(), "private-") {
		t.Error("managed plan announced success after a truncated JSON output")
	}
}

func TestShellManagedBlueprintCommandsUseStartupScopeWithoutCWDOrHistory(t *testing.T) {
	cleanEnvironment(t)
	fixture := newManagedCLIVault(t, true)
	t.Setenv("VAULT_ADDR", "private-invalid-inherited-address")
	t.Setenv("VAULT_TOKEN", "private-invalid-inherited-token")
	blueprintFile := blueprintCLIDocument(t, "app")
	stateFile := filepath.Join(t.TempDir(), "state.json")
	tokenFile := blueprintCLIInput(t, "private-managed-cli-token")
	commands := "blueprint adopt --file " + blueprintFile + " --state " + stateFile + "\n" +
		"blueprint plan --file " + blueprintFile + " --state " + stateFile + "\n" +
		"blueprint recover --file " + blueprintFile + " --state " + stateFile + "\nhistory\n"
	startup := []string{"shell", "--no-prompt", "--address", fixture.server.URL, "--namespace", "team", "--token-file", tokenFile, "--cwd", "/unused-kv-directory"}
	code, output, diagnostics := runShellCLI(strings.NewReader(commands), startup...)
	values := decodeShellOutputs(t, output)
	if code != 0 || diagnostics != "" || len(values) != 4 || !reflect.DeepEqual(values[3], []any{}) || fixture.writes.Load() != 0 || strings.Contains(output, "private-") {
		t.Error("managed shell commands lost their startup connection, inherited KV cwd or entered history")
	}
	for _, line := range []string{
		"blueprint apply --state " + stateFile + " --repair --address https://private-override --file " + blueprintFile,
		"blueprint recover --state " + stateFile + " --adopt-pending --namespace private-override --file " + blueprintFile,
		"blueprint adopt --file " + blueprintFile + " --token-file /private-override --state " + stateFile,
	} {
		requests := fixture.requests.Load()
		code, output, diagnostics = runShellCLI(strings.NewReader(line+"\npwd\n"), startup...)
		if code != 1 || output != "" || !strings.Contains(diagnostics, "connection and session options") || strings.Contains(diagnostics, "private-") || fixture.requests.Load() != requests {
			t.Error("boolean managed flags bypassed nested shell connection override detection")
		}
	}
}
