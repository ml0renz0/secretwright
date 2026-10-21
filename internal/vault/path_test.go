package vault_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func TestResolvePathCanonicalNavigation(t *testing.T) {
	for _, test := range []struct {
		name   string
		cwd    string
		target string
		want   string
	}{
		{name: "default root", target: ".", want: "/"},
		{name: "root identity", cwd: "/", target: "/", want: "/"},
		{name: "relative record", cwd: "/secret/app", target: "database", want: "/secret/app/database"},
		{name: "absolute overrides working directory", cwd: "/secret/app", target: "/other/key", want: "/other/key"},
		{name: "current directory", cwd: "/secret/app", target: ".", want: "/secret/app"},
		{name: "parent directory", cwd: "/secret/app", target: "..", want: "/secret"},
		{name: "sibling record", cwd: "/secret/app", target: "../shared/key", want: "/secret/shared/key"},
		{name: "cross mount navigation", cwd: "/secret/app", target: "../../other/key", want: "/other/key"},
		{name: "root parent stays root", cwd: "/", target: "..", want: "/"},
		{name: "multiple root parents stay root", cwd: "/secret", target: "../../../", want: "/"},
		{name: "parents clamped before descendant", cwd: "/", target: "../../secret/key", want: "/secret/key"},
		{name: "repeated separators", cwd: "/secret//app/", target: ".//nested///key/", want: "/secret/app/nested/key"},
		{name: "normalize absolute target", cwd: "/secret/app", target: "//team///kv/./folder/../key/", want: "/team/kv/key"},
		{name: "normalize working directory", cwd: "/team/temporary/../kv/", target: "./folder/../key", want: "/team/kv/key"},
		{name: "nested mount path", cwd: "/team/platform/kv", target: "app/database", want: "/team/platform/kv/app/database"},
		{name: "data is a logical key name", cwd: "/secret", target: "data/application", want: "/secret/data/application"},
		{name: "dot characters in names", cwd: "/secret", target: ".hidden/v1.2/..name", want: "/secret/.hidden/v1.2/..name"},
		{name: "unicode path names", cwd: "/secret/equipo", target: "contraseña/数据库", want: "/secret/equipo/contraseña/数据库"},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual, err := vault.ResolvePath(test.cwd, test.target)
			if err != nil {
				t.Fatalf("resolve logical path: %v", err)
			}
			if actual != test.want {
				t.Errorf("resolved path = %q, want %q", actual, test.want)
			}
		})
	}
}

func TestResolvePathRejectsInvalidLogicalInputWithoutEcho(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "URL escaped separator", value: "private-path-marker%2fkey"},
		{name: "URL escaped parent", value: "private-path-marker/%2e%2e/key"},
		{name: "double URL escaping", value: "private-path-marker/%252fkey"},
		{name: "literal percent", value: "private-path-marker/key%"},
		{name: "backslash", value: "private-path-marker\\key"},
		{name: "query", value: "private-path-marker?token=private-value"},
		{name: "fragment", value: "private-path-marker#private-value"},
		{name: "space", value: "private-path-marker key"},
		{name: "tab", value: "private-path-marker\tkey"},
		{name: "newline", value: "private-path-marker\nkey"},
		{name: "carriage return", value: "private-path-marker\rkey"},
		{name: "null byte", value: "private-path-marker\x00key"},
		{name: "delete control", value: "private-path-marker\x7fkey"},
		{name: "unicode whitespace", value: "private-path-marker\u00a0key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual, err := vault.ResolvePath("/secret", test.value)
			if actual != "" || !errors.Is(err, vault.ErrInvalidPath) {
				t.Fatalf("invalid logical target returned path %q and error %v", actual, err)
			}
			if strings.Contains(err.Error(), "private-path-marker") || strings.Contains(err.Error(), "private-value") {
				t.Error("logical path diagnostic echoed private input")
			}
		})
	}
}

func TestResolvePathRejectsInvalidWorkingDirectory(t *testing.T) {
	for _, cwd := range []string{
		"private-cwd-marker/relative",
		"/private-cwd-marker/%2fkey",
		"/private-cwd-marker\\key",
		"/private-cwd-marker?query",
		"/private-cwd-marker#fragment",
		"/private-cwd-marker key",
		"/private-cwd-marker\tkey",
		"/private-cwd-marker\x00key",
	} {
		t.Run("invalid working directory", func(t *testing.T) {
			actual, err := vault.ResolvePath(cwd, "key")
			if actual != "" || !errors.Is(err, vault.ErrInvalidPath) {
				t.Fatalf("invalid cwd returned path %q and error %v", actual, err)
			}
			if strings.Contains(err.Error(), "private-cwd-marker") {
				t.Error("working directory diagnostic echoed private input")
			}
		})
	}
}
