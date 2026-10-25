package vault_test

import (
	"errors"
	"path"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/ml0renz0/secretwright/internal/vault"
)

// These properties protect logical navigation independently of the mount or
// HTTP layer: arbitrary input must not introduce an ambiguous URL or escape
// above the logical root, and a resolved path must remain stable when reused.
func FuzzResolvePath(f *testing.F) {
	for _, seed := range [][2]string{
		{"", ""},
		{"/secret/app", "../../../other/key"},
		{"/team//kv/", "./folder/../key/"},
		{"/secret", "/other/key"},
		{"/secret", "contraseña/数据库"},
		{"/secret", "%252f/private-marker"},
		{"/secret", "key?token=private-marker"},
		{"/secret", "key\x00private-marker"},
		{"relative/private-marker", "key"},
		{"/secret", string([]byte{0xff, '/', 'k'})},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, cwd, target string) {
		if len(cwd)+len(target) > 8192 {
			t.Skip()
		}
		resolved, err := vault.ResolvePath(cwd, target)
		if err != nil {
			if !errors.Is(err, vault.ErrInvalidPath) || err.Error() != vault.ErrInvalidPath.Error() || resolved != "" {
				t.Fatal("invalid navigation must return only its fixed error and no path")
			}
			return
		}
		if !utf8.ValidString(resolved) || !strings.HasPrefix(resolved, "/") || path.Clean(resolved) != resolved {
			t.Fatal("successful navigation must produce a canonical absolute UTF-8 path")
		}
		if strings.ContainsAny(resolved, "%\\?#") || strings.IndexFunc(resolved, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}) >= 0 {
			t.Fatal("successful navigation retained URL delimiters or unsafe characters")
		}
		for _, segment := range strings.Split(strings.TrimPrefix(resolved, "/"), "/") {
			if segment == "." || segment == ".." {
				t.Fatal("successful navigation retained a parent or current-directory expression")
			}
		}
		again, err := vault.ResolvePath("/unrelated", resolved)
		if err != nil || again != resolved {
			t.Fatal("an absolute resolved path must be independent of its working directory")
		}
		identity, err := vault.ResolvePath(resolved, ".")
		if err != nil || identity != resolved {
			t.Fatal("current-directory navigation changed the resolved path")
		}
		if target != "" {
			withCurrent, err := vault.ResolvePath(cwd, target+"/./")
			if err != nil || withCurrent != resolved {
				t.Fatal("appending a current-directory segment changed the destination")
			}
		}
	})
}
