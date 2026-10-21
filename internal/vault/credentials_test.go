package vault_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func TestLoadTokenFromEnvironment(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		want         string
		wantError    bool
		wantUnauthed bool
	}{
		{name: "token", value: "environment-token-marker", want: "environment-token-marker"},
		{name: "surrounding whitespace", value: " \tenvironment-token-marker\r\n", want: "environment-token-marker"},
		{name: "absent", wantError: true, wantUnauthed: true},
		{name: "blank", value: " \t\r\n", wantError: true, wantUnauthed: true},
		{name: "internal space", value: "private-token-marker with-space", wantError: true},
		{name: "multiple lines", value: "private-token-marker\nsecond-line", wantError: true},
		{name: "internal tab", value: "private-token-marker\tsecond-part", wantError: true},
		{name: "oversized", value: strings.Repeat("private-token-marker", 4096), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearVaultEnvironment(t)
			t.Setenv("VAULT_TOKEN", test.value)
			got, err := vault.LoadToken("")
			if !test.wantError {
				if err != nil {
					t.Fatalf("load environment token: %v", err)
				}
				if got != test.want {
					t.Error("environment token did not match the expected trimmed value")
				}
				return
			}
			if err == nil || got != "" {
				t.Fatal("invalid or absent token must return an error and no token")
			}
			if errors.Is(err, vault.ErrUnauthenticated) != test.wantUnauthed {
				t.Errorf("unauthenticated classification = %v, want %v", errors.Is(err, vault.ErrUnauthenticated), test.wantUnauthed)
			}
			if strings.Contains(err.Error(), "private-token-marker") {
				t.Error("token validation error exposed token contents")
			}
		})
	}
}

func TestLoadTokenExplicitFileOverridesEnvironment(t *testing.T) {
	clearVaultEnvironment(t)
	// The explicit source wins even if the environment token is malformed.
	t.Setenv("VAULT_TOKEN", "invalid environment-token-marker")
	path := filepath.Join(t.TempDir(), "mounted-token")
	contents := []byte("file-token-marker\r\n")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := vault.LoadToken(path)
	if err != nil {
		t.Fatalf("load explicit token file: %v", err)
	}
	if got != "file-token-marker" {
		t.Error("explicit token file was not selected or trimmed")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(contents) {
		t.Error("reading a mounted token changed its file")
	}
}

func TestLoadTokenFileRejectsInvalidContents(t *testing.T) {
	tests := []struct {
		name         string
		contents     string
		wantUnauthed bool
	}{
		{name: "empty", wantUnauthed: true},
		{name: "blank", contents: " \r\n\t", wantUnauthed: true},
		{name: "multiple lines", contents: "private-file-token-marker\nsecond-token"},
		{name: "internal space", contents: "private-file-token-marker another-part"},
		{name: "internal tab", contents: "private-file-token-marker\tanother-part"},
		{name: "oversized", contents: strings.Repeat("private-file-token-marker", 4096)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearVaultEnvironment(t)
			t.Setenv("VAULT_TOKEN", "valid-environment-token-must-not-be-used")
			path := filepath.Join(t.TempDir(), "private-path-marker.token")
			if err := os.WriteFile(path, []byte(test.contents), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := vault.LoadToken(path)
			if err == nil || got != "" {
				t.Fatal("invalid explicit token file must fail without falling back to the environment")
			}
			if errors.Is(err, vault.ErrUnauthenticated) != test.wantUnauthed {
				t.Errorf("unauthenticated classification = %v, want %v", errors.Is(err, vault.ErrUnauthenticated), test.wantUnauthed)
			}
			for _, marker := range []string{"private-file-token-marker", "private-path-marker"} {
				if strings.Contains(err.Error(), marker) {
					t.Error("token file validation error exposed private input")
				}
			}
		})
	}
}

func TestLoadTokenFileReadErrorsAreSafe(t *testing.T) {
	for _, test := range []string{"missing file", "directory"} {
		t.Run(test, func(t *testing.T) {
			clearVaultEnvironment(t)
			t.Setenv("VAULT_TOKEN", "valid-environment-token-must-not-be-used")
			path := filepath.Join(t.TempDir(), "private-path-marker")
			if test == "directory" {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			got, err := vault.LoadToken(path)
			if err == nil || got != "" {
				t.Fatal("unreadable token source must fail without falling back to the environment")
			}
			if errors.Is(err, vault.ErrUnauthenticated) {
				t.Error("token source read error was classified as an authentication rejection")
			}
			if strings.Contains(err.Error(), "private-path-marker") || strings.Contains(err.Error(), "environment-token") {
				t.Error("token source read error exposed input")
			}
		})
	}
}

func TestLoadTokenAcceptsMaximumTokenSize(t *testing.T) {
	clearVaultEnvironment(t)
	const maximumTokenBytes = 64 * 1024
	want := strings.Repeat("a", maximumTokenBytes)
	t.Setenv("VAULT_TOKEN", want)
	got, err := vault.LoadToken("")
	if err != nil || got != want {
		t.Fatal("a token at the documented maximum size must be accepted from the environment")
	}
	path := filepath.Join(t.TempDir(), "maximum-token")
	if err := os.WriteFile(path, []byte(want), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = vault.LoadToken(path)
	if err != nil || got != want {
		t.Fatal("a token at the documented maximum size must be accepted from an explicit file")
	}
}
