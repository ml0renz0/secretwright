package cli_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/cli"
	"github.com/ml0renz0/secretwright/internal/configuration"
)

const keytabCLIPolicy = `api_version: secretwright/keytab/v1
name: application
principal: {realm: EXAMPLE.TEST, components: [HTTP, app.example.test]}
minimum_kvno: 3
allowed_enctypes: [17, 18, 19, 20]
required_enctypes: [18]
allow_other_principals: false
`

func keytabCLIBinary() []byte {
	var entry bytes.Buffer
	_ = binary.Write(&entry, binary.BigEndian, uint16(2))
	for _, text := range []string{"EXAMPLE.TEST", "HTTP", "app.example.test"} {
		_ = binary.Write(&entry, binary.BigEndian, uint16(len(text)))
		_, _ = entry.WriteString(text)
	}
	_ = binary.Write(&entry, binary.BigEndian, uint32(2))
	_ = binary.Write(&entry, binary.BigEndian, uint32(2100000000))
	_ = entry.WriteByte(3)
	_ = binary.Write(&entry, binary.BigEndian, uint16(18))
	_ = binary.Write(&entry, binary.BigEndian, uint16(32))
	key := make([]byte, 32)
	copy(key, []byte("private-f12-key-material-marker"))
	_, _ = entry.Write(key)
	_ = binary.Write(&entry, binary.BigEndian, uint32(3))
	var result bytes.Buffer
	_, _ = result.Write([]byte{5, 2})
	_ = binary.Write(&result, binary.BigEndian, int32(entry.Len()))
	_, _ = result.Write(entry.Bytes())
	return result.Bytes()
}

func keytabCLIFile(t *testing.T, body []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private-keytab-file")
	if os.WriteFile(path, body, 0o600) != nil || os.Chmod(path, mode) != nil {
		t.Fatal("could not prepare private keytab fixture")
	}
	return path
}

func keytabCLISafe(t *testing.T, output, diagnostics string, raw []byte) {
	t.Helper()
	key := make([]byte, 32)
	copy(key, []byte("private-f12-key-material-marker"))
	for _, private := range []string{"private-f12-key-material-marker", "private-f12-operator", "private-f12-upstream", base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(key)} {
		if private != "" && strings.Contains(output+diagnostics, private) {
			t.Error("keytab output or diagnostics exposed private material")
		}
	}
}

func TestKeytabOfflineExamplesSchemaAndHelpIgnoreVaultEnvironment(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CACERT", "/private-missing-ca")
	t.Setenv("VAULT_TOKEN", "private-f12-operator")
	for _, format := range []string{"", "yaml", "json"} {
		args := []string{"keytab", "example"}
		if format != "" {
			args = append(args, "--format", format)
		}
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		document, err := configuration.DecodeObject(strings.NewReader(output))
		if code != 0 || diagnostics != "" || err != nil || document["api_version"] != "secretwright/keytab/v1" || json.Valid([]byte(output)) != (format == "json") {
			t.Error("keytab example did not preserve offline YAML defaults and explicit JSON")
		}
	}
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "keytab", "schema")
	var schema map[string]any
	if code != 0 || diagnostics != "" || json.Unmarshal([]byte(output), &schema) != nil || schema["$id"] != "urn:secretwright:keytab:v1" {
		t.Error("keytab schema was not available offline")
	}
	for _, prefix := range [][]string{{"keytab"}, {"keytab", "schema"}, {"keytab", "example"}, {"keytab", "inspect"}, {"keytab", "validate"}, {"keytab", "import"}, {"keytab", "export"}} {
		args := append(append([]string{}, prefix...), "--help")
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		if code != 0 || diagnostics != "" || !strings.Contains(output, "Usage:") {
			t.Error("keytab help selected credentials or network")
		}
	}
}

func TestKeytabInspectionAndPolicyValidationReturnOnlyUnauthenticatedMetadata(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "private-invalid-address")
	t.Setenv("VAULT_CLIENT_TIMEOUT", "private-invalid-timeout")
	raw := keytabCLIBinary()
	file := keytabCLIFile(t, raw, 0o600)
	policy := keytabCLIFile(t, []byte(keytabCLIPolicy), 0o644)
	code, output, diagnostics := runWriteCLI(f03PanicReader{}, "keytab", "inspect", "--file", file)
	var inspected struct {
		Version int `json:"version"`
		AuthenticationChecked bool `json:"authentication_checked"`
		Entries []struct {
			Realm string `json:"realm"`
			Components []string `json:"components"`
			KVNO uint32 `json:"kvno"`
			Enctype uint16 `json:"enctype"`
			KeyLength int `json:"key_length"`
		} `json:"entries"`
	}
	if code != 0 || diagnostics != "" || json.Unmarshal([]byte(output), &inspected) != nil || inspected.Version != 2 || inspected.AuthenticationChecked || len(inspected.Entries) != 1 || inspected.Entries[0].Realm != "EXAMPLE.TEST" || inspected.Entries[0].KVNO != 3 || inspected.Entries[0].Enctype != 18 || inspected.Entries[0].KeyLength != 32 {
		t.Fatal("keytab inspection did not project exact safe binary metadata")
	}
	keytabCLISafe(t, output, diagnostics, raw)
	for _, flags := range [][]string{nil, {"--policy", policy}} {
		args := append([]string{"keytab", "validate", "--file", file}, flags...)
		code, output, diagnostics = runWriteCLI(f03PanicReader{}, args...)
		var report struct {
			Valid bool `json:"valid"`
			PolicyChecked bool `json:"policy_checked"`
			AuthenticationChecked bool `json:"authentication_checked"`
		}
		if code != 0 || diagnostics != "" || json.Unmarshal([]byte(output), &report) != nil || !report.Valid || report.AuthenticationChecked || report.PolicyChecked != (len(flags) != 0) {
			t.Error("keytab validation confused structural/policy checks with Kerberos authentication")
		}
		keytabCLISafe(t, output, diagnostics, raw)
	}
	foreign := keytabCLIFile(t, []byte(strings.Replace(keytabCLIPolicy, "app.example.test", "foreign.example.test", 1)), 0o644)
	code, output, diagnostics = runWriteCLI(f03PanicReader{}, "keytab", "validate", "--file", file, "--policy", foreign)
	var negative struct {
		Valid bool `json:"valid"`
		Reason string `json:"reason"`
	}
	if code != 4 || diagnostics == "" || json.Unmarshal([]byte(output), &negative) != nil || negative.Valid || negative.Reason == "" {
		t.Error("negative keytab policy validation did not preserve its safe report and conflict code")
	}
	keytabCLISafe(t, output, diagnostics, raw)
}

func TestKeytabInvalidInputsAndOutputConflictsFailBeforeOperatorOrHTTP(t *testing.T) {
	cleanEnvironment(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	raw := keytabCLIBinary()
	file := keytabCLIFile(t, raw, 0o600)
	public := keytabCLIFile(t, raw, 0o644)
	invalid := keytabCLIFile(t, []byte("private-f12-upstream"), 0o600)
	badPolicy := keytabCLIFile(t, []byte(strings.Replace(keytabCLIPolicy, "minimum_kvno: 3", "minimum_kvno: 0", 1)), 0o644)
	foreignPolicy := keytabCLIFile(t, []byte(strings.Replace(keytabCLIPolicy, "app.example.test", "foreign.example.test", 1)), 0o644)
	missingOperator := filepath.Join(t.TempDir(), "operator-missing")
	output := keytabCLIFile(t, []byte("foreign-file-kept"), 0o600)
	for _, test := range []struct {
		args []string
		code int
	}{
		{[]string{"keytab", "inspect", "--file", public}, 1},
		{[]string{"keytab", "inspect", "--file", invalid}, 1},
		{[]string{"keytab", "import", "--file", invalid, "--mount", "secret", "--path", "/secret/keytabs/app"}, 1},
		{[]string{"keytab", "import", "--file", public, "--mount", "secret", "--path", "/secret/keytabs/app"}, 1},
		{[]string{"keytab", "import", "--file", file, "--policy", badPolicy, "--mount", "secret", "--path", "/secret/keytabs/app"}, 1},
		{[]string{"keytab", "import", "--file", file, "--policy", foreignPolicy, "--mount", "secret", "--path", "/secret/keytabs/app"}, 4},
		{[]string{"keytab", "export", "--mount", "secret", "--path", "/secret/keytabs/app", "--out", output}, 4},
	} {
		args := append(append([]string{}, test.args...), "--address", server.URL, "--token-file", missingOperator)
		if test.args[1] == "inspect" {
			args = test.args
		}
		code, stdout, stderr := runWriteCLI(f03PanicReader{}, args...)
		if code != test.code || stderr == "" {
			t.Error("keytab preflight did not reject its local input before operator loading")
		}
		keytabCLISafe(t, stdout, stderr, raw)
	}
	if requests.Load() != 0 {
		t.Error("invalid local keytab input contacted Vault")
	}
	kept, err := os.ReadFile(output)
	if err != nil || string(kept) != "foreign-file-kept" {
		t.Error("keytab output preflight overwrote an existing file")
	}
	for _, args := range [][]string{
		{"keytab", "inspect", "--file", "-"}, {"keytab", "example", "--format", "xml"},
		{"keytab", "schema", "--format", "json"}, {"keytab", "validate", "--file", file, "--cwd", "/"},
		{"keytab", "import", "--file", file, "--mount", "secret", "--path", "/secret/keytabs/app", "--cas", "-1"},
		{"keytab", "import", "--file", file, "--mount", "secret", "--path", "/secret/keytabs/app", "--force"},
		{"keytab", "import", "--file", file, "--mount", "secret", "--path", "/secret/keytabs/app", "--version", "1"},
		{"keytab", "export", "--mount", "secret", "--path", "/secret/keytabs/app", "--out", "-"},
		{"keytab", "export", "--mount", "secret", "--path", "/secret/keytabs/app", "--out", output, "--version", "0"},
		{"keytab", "export", "--mount", "secret", "--path", "/secret/keytabs/app", "--out", output, "--cas", "0"},
		{"keytab", "export", "--mount", "secret", "--path", "/secret/../foreign/key", "--out", output},
		{"keytab", "export", "--mount", "secret", "--path", "/secret/keytabs/app", "--out", output, "--kv-version", "2"},
		{"keytab", "inspect", "--file", file, "positional"},
	} {
		if code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...); code != 1 || diagnostics == "" {
			t.Error("unsupported keytab option or unsafe path was accepted")
			keytabCLISafe(t, output, diagnostics, raw)
		}
	}
}

func TestKeytabImportUsesCASAndNeverReportsTheEnvelope(t *testing.T) {
	cleanEnvironment(t)
	raw := keytabCLIBinary()
	file := keytabCLIFile(t, raw, 0o600)
	operator := keytabCLIFile(t, []byte("private-f12-operator\n"), 0o600)
	var requests atomic.Int32
	var wantedCAS atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		cas := int(wantedCAS.Load())
		if r.Method != http.MethodPut || r.URL.Path != "/v1/secret/data/keytabs/app" || r.URL.RawQuery != "" || r.Header.Get("X-Vault-Token") != "private-f12-operator" || r.Header.Get("X-Vault-Namespace") != "team" {
			t.Error("keytab import changed its exact operator, namespace, mount or method")
		}
		var body struct {
			Data map[string]any `json:"data"`
			Options struct { CAS int `json:"cas"` } `json:"options"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Options.CAS != cas || len(body.Data) != 3 || body.Data["api_version"] != "secretwright/keytab/v1" || body.Data["encoding"] != "base64" || body.Data["data"] != base64.StdEncoding.EncodeToString(raw) {
			t.Error("keytab import changed its explicit CAS or canonical binary envelope")
		}
		accessReply(t, w, map[string]any{"data": map[string]any{"version": cas + 1}})
	}))
	defer server.Close()
	for _, cas := range []int{0, 3} {
		wantedCAS.Store(int32(cas))
		args := []string{"keytab", "import", "--file", file, "--mount", "secret", "--path", "/secret/keytabs/app", "--address", server.URL, "--namespace", "team", "--token-file", operator}
		if cas != 0 {
			args = append(args, "--cas", "3")
		}
		code, output, diagnostics := runWriteCLI(f03PanicReader{}, args...)
		var report struct {
			Operation string `json:"operation"`
			Version int `json:"version"`
			Report struct { AuthenticationChecked bool `json:"authentication_checked"` } `json:"report"`
		}
		if code != 0 || diagnostics != "" || json.Unmarshal([]byte(output), &report) != nil || report.Operation != "import" || report.Version != cas+1 || report.Report.AuthenticationChecked {
			t.Error("keytab import did not report its confirmed revision as safe metadata")
		}
		keytabCLISafe(t, output, diagnostics, raw)
	}
	if requests.Load() != 2 {
		t.Error("keytab import retried or consulted unrelated Vault APIs")
	}
	wantedCAS.Store(0)
	for _, writer := range []io.Writer{failedWriter{}, blueprintShortWriter{}} {
		var diagnostics bytes.Buffer
		args := []string{"keytab", "import", "--file", file, "--mount", "secret", "--path", "/secret/keytabs/app", "--address", server.URL, "--namespace", "team", "--token-file", operator}
		if code := cli.RunWithInput(context.Background(), args, f03PanicReader{}, writer, &diagnostics, "test"); code != 5 || diagnostics.Len() == 0 {
			t.Error("confirmed keytab import ignored failed metadata output or lost its partial outcome")
		}
		keytabCLISafe(t, "", diagnostics.String(), raw)
	}
}

func TestKeytabExportPreservesExactHistoricalBytesAndPrivateOutput(t *testing.T) {
	cleanEnvironment(t)
	raw := keytabCLIBinary()
	operator := keytabCLIFile(t, []byte("private-f12-operator\n"), 0o600)
	var requests atomic.Int32
	var wantedVersion atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		requested := int(wantedVersion.Load())
		wantQuery := ""
		if requested != 0 {
			wantQuery = "5"
		}
		if r.Method != http.MethodGet || r.URL.Path != "/v1/secret/data/keytabs/app" || r.URL.Query().Get("version") != wantQuery || r.Header.Get("X-Vault-Token") != "private-f12-operator" || r.Header.Get("X-Vault-Namespace") != "team" {
			t.Error("keytab export changed its exact version, operator or path")
		}
		version := 7
		if requested != 0 {
			version = requested
		}
		accessReply(t, w, map[string]any{"data": map[string]any{"data": map[string]any{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": base64.StdEncoding.EncodeToString(raw)}, "metadata": map[string]any{"version": version, "deletion_time": "", "destroyed": false}}})
	}))
	defer server.Close()
	for _, version := range []int{0, 5} {
		wantedVersion.Store(int32(version))
		output := filepath.Join(t.TempDir(), "download.keytab")
		args := []string{"keytab", "export", "--mount", "secret", "--path", "/secret/keytabs/app", "--out", output, "--address", server.URL, "--namespace", "team", "--token-file", operator}
		if version != 0 {
			args = append(args, "--version", "5")
		}
		code, stdout, stderr := runWriteCLI(f03PanicReader{}, args...)
		got, err := os.ReadFile(output)
		info, statErr := os.Lstat(output)
		var report struct { Version int `json:"version"` }
		wantVersion := 7
		if version != 0 {
			wantVersion = version
		}
		if code != 0 || stderr != "" || err != nil || !bytes.Equal(got, raw) || statErr != nil || info.Mode() != 0o600 || json.Unmarshal([]byte(stdout), &report) != nil || report.Version != wantVersion {
			t.Error("keytab export changed binary bytes, private permissions or snapshot revision")
		}
		keytabCLISafe(t, stdout, stderr, raw)
	}
	if requests.Load() != 2 {
		t.Error("keytab export performed discovery, a separate revision lookup or a fallback read")
	}
}

func TestKeytabOfflineShortWritesAndCanceledOnlineOperationsAreChecked(t *testing.T) {
	cleanEnvironment(t)
	raw := keytabCLIBinary()
	file := keytabCLIFile(t, raw, 0o600)
	for _, args := range [][]string{{"keytab", "--help"}, {"keytab", "schema"}, {"keytab", "example"}, {"keytab", "inspect", "--file", file}, {"keytab", "validate", "--file", file}} {
		for _, writer := range []io.Writer{failedWriter{}, blueprintShortWriter{}} {
			var diagnostics bytes.Buffer
			if code := cli.RunWithInput(context.Background(), args, f03PanicReader{}, writer, &diagnostics, "test"); code != 1 || diagnostics.Len() == 0 {
				t.Error("keytab offline command ignored failed or short stdout")
			}
			keytabCLISafe(t, "", diagnostics.String(), raw)
		}
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	operator := keytabCLIFile(t, []byte("private-f12-operator\n"), 0o600)
	output := filepath.Join(t.TempDir(), "canceled.keytab")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, args := range [][]string{
		{"keytab", "import", "--file", file, "--mount", "secret", "--path", "/secret/keytabs/app"},
		{"keytab", "export", "--mount", "secret", "--path", "/secret/keytabs/app", "--out", output},
	} {
		args = append(args, "--address", server.URL, "--token-file", operator)
		var stdout, stderr bytes.Buffer
		if code := cli.RunWithInput(ctx, args, f03PanicReader{}, &stdout, &stderr, "test"); code != 130 || stderr.Len() == 0 || stdout.Len() != 0 {
			t.Error("canceled keytab operation did not stop before effects")
		}
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) || requests.Load() != 0 {
		t.Error("canceled keytab transfer left an output or contacted Vault")
	}
}
