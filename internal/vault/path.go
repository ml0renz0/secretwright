package vault

import (
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ResolvePath resolves a logical Vault path independently of the API's KV v2
// data and metadata prefixes. Parent navigation is bounded by the logical root.
func ResolvePath(cwd, target string) (string, error) {
	if cwd == "" {
		cwd = "/"
	}
	if !strings.HasPrefix(cwd, "/") || !validLogicalText(cwd) || !validLogicalText(target) {
		return "", ErrInvalidPath
	}
	if strings.HasPrefix(target, "/") {
		return path.Clean(target), nil
	}
	return path.Join(cwd, target), nil
}

func validLogicalText(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsAny(value, "%\\?#") &&
		strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) < 0
}

// A mount is a declared prefix, not a navigation expression. Reject dot and
// empty interior segments instead of silently changing the declared scope.
func canonicalMount(value string) (string, error) {
	if !validLogicalText(value) {
		return "", ErrInvalidPath
	}
	value = strings.Trim(value, "/")
	if value == "" {
		return "", ErrInvalidPath
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", ErrInvalidPath
		}
	}
	return value + "/", nil
}

func pathInMount(logical string, mount Mount) bool {
	prefix := "/" + strings.TrimSuffix(mount.Path, "/")
	return logical == prefix || strings.HasPrefix(logical, prefix+"/")
}
