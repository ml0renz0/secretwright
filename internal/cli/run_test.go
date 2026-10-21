package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/cli"
	"github.com/ml0renz0/secretwright/internal/vault"
)

func cleanEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(name, "VAULT_") {
			t.Setenv(name, "")
		}
	}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		t.Setenv(name, "")
	}
	t.Setenv("NO_PROXY", "127.0.0.1,localhost,::1")
	t.Setenv("no_proxy", "127.0.0.1,localhost,::1")
}

func TestHelpAndVersionDoNotConnectToVault(t *testing.T) {
	cleanEnvironment(t)
	t.Setenv("VAULT_ADDR", "://invalid")
	t.Setenv("VAULT_CACERT", "/does-not-exist/secretwright-ca.pem")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "default", want: "Usage:"},
		{name: "help", args: []string{"help"}, want: "Usage:"},
		{name: "short help", args: []string{"-h"}, want: "Usage:"},
		{name: "long help", args: []string{"--help"}, want: "Usage:"},
		{name: "version", args: []string{"version"}, want: "secretwright test-version\n"},
		{name: "long version", args: []string{"--version"}, want: "secretwright test-version\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := cli.Run(context.Background(), tc.args, &stdout, &stderr, "test-version"); code != 0 {
				t.Fatalf("exit code = %d, want 0; stderr = %q", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), tc.want) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tc.want)
			}
			if stderr.Len() != 0 {
				t.Errorf("unexpected stderr: %q", stderr.String())
			}
		})
	}
}

func TestInvalidCommandsDoNotEchoArguments(t *testing.T) {
	const sensitiveArgument = "sensitive-command-argument"
	for _, args := range [][]string{
		{sensitiveArgument},
		{"status", sensitiveArgument},
	} {
		var stdout, stderr bytes.Buffer
		if code := cli.Run(context.Background(), args, &stdout, &stderr, "test"); code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
		if stdout.Len() != 0 || stderr.Len() == 0 {
			t.Errorf("expected only stderr, got stdout = %q, stderr = %q", stdout.String(), stderr.String())
		}
		if strings.Contains(stderr.String(), sensitiveArgument) {
			t.Error("diagnostic echoed an untrusted argument")
		}
	}
}

func TestStatusReportsHealthAndExitCode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		health vault.Status
		code   int
	}{
		{name: "active", health: vault.Status{Initialized: true, Version: "2.2.0", ClusterName: "test", ClusterID: "cluster-id"}},
		{name: "standby", health: vault.Status{Initialized: true, Standby: true, Version: "2.2.0"}},
		{name: "sealed", health: vault.Status{Initialized: true, Sealed: true, Version: "2.2.0"}, code: 2},
		{name: "uninitialized", health: vault.Status{Sealed: true, Version: "2.2.0"}, code: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnvironment(t)
			t.Setenv("VAULT_TOKEN", "must-not-be-sent")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/sys/health" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if r.Header.Get("X-Vault-Token") != "" {
					t.Error("health request sent an inherited Vault token")
				}
				w.Header().Set("Content-Type", "application/json")
				if tc.health.Sealed || !tc.health.Initialized || tc.health.Standby {
					w.WriteHeader(299)
				}
				if err := json.NewEncoder(w).Encode(tc.health); err != nil {
					t.Errorf("write fixture: %v", err)
				}
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			var stdout, stderr bytes.Buffer
			if code := cli.Run(context.Background(), []string{"status"}, &stdout, &stderr, "test"); code != tc.code {
				t.Fatalf("exit code = %d, want %d; stderr = %q", code, tc.code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("unexpected stderr: %q", stderr.String())
			}
			var got vault.Status
			decoder := json.NewDecoder(&stdout)
			if err := decoder.Decode(&got); err != nil {
				t.Fatalf("stdout is not a JSON health report: %v", err)
			}
			if got != tc.health {
				t.Errorf("health = %+v, want %+v", got, tc.health)
			}
			if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
				t.Errorf("expected exactly one JSON object, trailing decode returned %v", err)
			}
		})
	}
}

func TestStatusErrorsKeepStdoutEmpty(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "upstream failure", status: http.StatusForbidden, body: `{"errors":["sensitive-upstream-value"]}`},
		{name: "invalid JSON", status: http.StatusOK, body: "sensitive-upstream-value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnvironment(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			t.Setenv("VAULT_ADDR", server.URL)
			var stdout, stderr bytes.Buffer
			if code := cli.Run(context.Background(), []string{"status"}, &stdout, &stderr, "test"); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if stdout.Len() != 0 || stderr.Len() == 0 {
				t.Errorf("expected only stderr, got stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), "sensitive-upstream-value") {
				t.Error("diagnostic leaked an upstream response body")
			}
		})
	}
	for _, name := range []string{"invalid address", "unreachable Vault"} {
		t.Run(name, func(t *testing.T) {
			cleanEnvironment(t)
			address := "://invalid"
			if name == "unreachable Vault" {
				server := httptest.NewServer(http.NotFoundHandler())
				address = server.URL
				server.Close()
			}
			t.Setenv("VAULT_ADDR", address)
			var stdout, stderr bytes.Buffer
			if code := cli.Run(context.Background(), []string{"status"}, &stdout, &stderr, "test"); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if stdout.Len() != 0 || stderr.Len() == 0 {
				t.Errorf("expected only stderr, got stdout = %q, stderr = %q", stdout.String(), stderr.String())
			}
		})
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) {
	return 0, errors.New("output unavailable")
}

func TestOutputFailuresReturnError(t *testing.T) {
	cleanEnvironment(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"initialized":true,"sealed":false,"standby":false,"version":"2.2.0"}`)
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	for _, command := range []string{"help", "version", "status"} {
		t.Run(command, func(t *testing.T) {
			var stderr bytes.Buffer
			if code := cli.Run(context.Background(), []string{command}, failedWriter{}, &stderr, "test"); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if !strings.Contains(stderr.String(), "could not write output") {
				t.Errorf("missing output failure diagnostic: %q", stderr.String())
			}
		})
	}
}
