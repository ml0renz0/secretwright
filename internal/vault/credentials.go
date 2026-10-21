package vault

import (
	"errors"
	"io"
	"os"
	"strings"
	"unicode"
)

const maximumTokenBytes = 64 * 1024

// LoadToken reads an explicit mounted file or VAULT_TOKEN. It does not consult
// home-directory helpers, fall back from a broken file, or persist credentials.
func LoadToken(path string) (string, error) {
	if path == "" {
		return normalizeToken(os.Getenv("VAULT_TOKEN"))
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("could not open the token file")
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maximumTokenBytes+1))
	if err != nil {
		return "", errors.New("could not read the token file")
	}
	return normalizeToken(string(contents))
}

func normalizeToken(value string) (string, error) {
	if len(value) > maximumTokenBytes {
		return "", errors.New("token exceeds the 64 KiB size limit")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrUnauthenticated
	}
	if strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return "", errors.New("token contains invalid whitespace or control characters")
	}
	return value, nil
}
