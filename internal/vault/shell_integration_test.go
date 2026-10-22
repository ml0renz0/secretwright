//go:build integration

package vault_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/cli"
)

func decodeIntegrationSession(t *testing.T, output string) []any {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.UseNumber()
	var results []any
	for {
		var value any
		err := decoder.Decode(&value)
		if err == io.EOF {
			return results
		}
		if err != nil {
			t.Fatal("real session stdout contained a prompt, command echo, or malformed JSON")
		}
		results = append(results, value)
	}
}

func TestIntegrationShellSharesKVCommandsAndSessionDirectory(t *testing.T) {
	fixture := prepareKVIntegrationFixture(t)
	writer := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-f04-%d", time.Now().UnixNano()), integrationWritePolicy(fixture))
	directory := t.TempDir()
	tokenFile := filepath.Join(directory, "token")
	dataFile := filepath.Join(directory, "private values.json")
	if err := os.WriteFile(tokenFile, []byte(writer), 0o600); err != nil {
		t.Fatal("could not prepare the private session credential")
	}
	data := map[string]any{"value": "private-f04-session-value", "identifier": "9007199254740993123456789"}
	encoded, err := json.Marshal(data)
	if err != nil || os.WriteFile(dataFile, encoded, 0o600) != nil {
		t.Fatal("could not prepare the private session input")
	}
	cwd := "/" + fixture.v2 + "allowed"
	commands := fmt.Sprintf("cd %s\npwd\nput --file %q session-created\ncat session-created\nversions session-created\nhistory\n", cwd, dataFile)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var output, diagnostics bytes.Buffer
	code := cli.RunWithInput(ctx, []string{"shell", "--no-prompt", "--token-file", tokenFile}, strings.NewReader(commands), &output, &diagnostics, "test")
	if code != 0 || diagnostics.Len() != 0 {
		t.Fatal("real Vault session could not navigate and use its scoped credential")
	}
	results := decodeIntegrationSession(t, output.String())
	if len(results) != 6 || !reflect.DeepEqual(results[0], map[string]any{"path": cwd}) || !reflect.DeepEqual(results[1], map[string]any{"path": cwd}) || !reflect.DeepEqual(results[3], data) {
		t.Fatal("real session did not preserve cwd or its requested readback")
	}
	written, ok := results[2].(map[string]any)
	if !ok || written["path"] != cwd+"/session-created" || written["version"] != json.Number("1") || len(written) != 3 {
		t.Fatal("session write exposed data or bypassed the common mutation engine")
	}
	history, ok := results[4].(map[string]any)
	if !ok || history["current_version"] != json.Number("1") {
		t.Fatal("session could not inspect its created version")
	}
	wantHistory := []any{"cd " + cwd, "pwd", "versions session-created"}
	if !reflect.DeepEqual(results[5], wantHistory) {
		t.Fatal("session searchable history retained a data read, mutation, or data filename")
	}
	if strings.Contains(output.String()+diagnostics.String(), writer) || strings.Contains(output.String()+diagnostics.String(), dataFile) {
		t.Fatal("session exposed a credential or private data filename")
	}
}

func TestIntegrationShellStopsAtDeniedPathAndPreservesCASGuard(t *testing.T) {
	fixture := prepareKVIntegrationFixture(t)
	directory := t.TempDir()
	tokenFile := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenFile, []byte(fixture.scopedToken), 0o600); err != nil {
		t.Fatal("could not prepare the private read-only session credential")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var output, diagnostics bytes.Buffer
	commands := "cd /" + fixture.v2 + "allowed\ncat /" + fixture.v2 + "denied/item\npwd\n"
	code := cli.RunWithInput(ctx, []string{"shell", "--token-file", tokenFile}, strings.NewReader(commands), &output, &diagnostics, "test")
	if code != 2 || diagnostics.Len() == 0 || len(decodeIntegrationSession(t, output.String())) != 1 {
		t.Fatal("real batch session continued after a denied path or changed its exit code")
	}
	if strings.Contains(output.String()+diagnostics.String(), fixture.scopedToken) || strings.Contains(diagnostics.String(), "private-kv-") {
		t.Fatal("denied session exposed a credential or secret value")
	}
	writer := createKVIntegrationPolicyToken(t, fixture.admin, fmt.Sprintf("secretwright-f04-cas-%d", time.Now().UnixNano()), integrationWritePolicy(fixture))
	if err := os.WriteFile(tokenFile, []byte(writer), 0o600); err != nil {
		t.Fatal("could not prepare the mutation session credential")
	}
	dataFile := filepath.Join(directory, "values.json")
	if err := os.WriteFile(dataFile, []byte(`{"value":"private-f04-create-only"}`), 0o600); err != nil {
		t.Fatal("could not prepare create-only session data")
	}
	output.Reset()
	diagnostics.Reset()
	commands = fmt.Sprintf("put --file %q item\npwd\n", dataFile)
	code = cli.RunWithInput(ctx, []string{"shell", "--cwd", "/" + fixture.v2 + "allowed", "--token-file", tokenFile}, strings.NewReader(commands), &output, &diagnostics, "test")
	if code != 4 || output.Len() != 0 || diagnostics.Len() == 0 {
		t.Fatal("session bypassed create-only CAS or continued after a conflict")
	}
}
