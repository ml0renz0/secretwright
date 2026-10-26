package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const privateTokenLimit = 64 << 10
const privateDocumentLimit = 1 << 20

func privateRegular(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func privateDirectory(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode().Perm() == 0o700 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func privateDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func privateValue(body []byte, token bool) (PrivateFile, error) {
	limit := privateDocumentLimit
	if token { limit = privateTokenLimit }
	if len(body) == 0 || len(body) > limit || !utf8.Valid(body) || strings.IndexByte(string(body), 0) >= 0 {
		return PrivateFile{}, ErrInvalidLifecycle
	}
	value := PrivateFile{Data: append([]byte(nil), body...), Digest: privateDigest(body)}
	if token {
		value.Token = strings.TrimSpace(string(body))
		if value.Token == "" || strings.IndexFunc(value.Token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return PrivateFile{}, ErrInvalidLifecycle
		}
	}
	return value, nil
}

// readPrivateBytes rejects a final symlink and verifies that the descriptor and
// path still identify the same private regular file after the bounded read.
func readPrivateBytes(path string, limit int64) ([]byte, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil { return nil, nil, ErrIO }
	if !privateRegular(before) { return nil, nil, ErrInvalidLifecycle }
	file, err := os.Open(path)
	if err != nil { return nil, nil, ErrIO }
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !privateRegular(opened) || !os.SameFile(before, opened) { return nil, nil, ErrConflict }
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil { return nil, nil, ErrIO }
	if int64(len(body)) > limit { return nil, nil, ErrInvalidLifecycle }
	after, statErr := file.Stat()
	current, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !privateRegular(after) || !privateRegular(current) || !os.SameFile(opened, after) || !os.SameFile(opened, current) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return nil, nil, ErrConflict
	}
	return body, current, nil
}

func readPrivateToken(path string) (PrivateFile, os.FileInfo, error) {
	body, identity, err := readPrivateBytes(path, privateTokenLimit)
	if err != nil { return PrivateFile{}, nil, err }
	value, err := privateValue(body, true)
	if err != nil { return PrivateFile{}, nil, err }
	return value, identity, nil
}

// ReadPrivate reads an existing raw token without following a final symlink or
// disclosing its contents or path in an error. Data retains the exact bytes.
func ReadPrivate(path string) (PrivateFile, error) {
	value, _, err := readPrivateToken(path)
	return value, err
}

func removePrivateOwned(path string, identity os.FileInfo) {
	current, err := os.Lstat(path)
	if err == nil && identity != nil && current.Mode().IsRegular() && os.SameFile(identity, current) { _ = os.Remove(path) }
}

func syncPrivateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil { return ErrIO }
	defer directory.Close()
	if directory.Sync() != nil { return ErrIO }
	return nil
}

// preparePrivateFile constructs a complete sibling before it can replace a
// destination. The temporary name and contents never enter an error message.
func preparePrivateFile(path string, body []byte, owner os.FileInfo) (string, os.FileInfo, error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".secretwright-private-*")
	if err != nil { return "", nil, ErrIO }
	name := file.Name()
	identity, err := file.Stat()
	if err != nil { _ = file.Close(); _ = os.Remove(name); return "", nil, ErrIO }
	abort := func() (string, os.FileInfo, error) {
		_ = file.Close()
		removePrivateOwned(name, identity)
		return "", nil, ErrIO
	}
	if file.Chmod(0o600) != nil { return abort() }
	if owner != nil && preservePrivateOwner(file, owner) != nil { return abort() }
	written, err := file.Write(body)
	if err != nil || written != len(body) || file.Sync() != nil { return abort() }
	identity, err = file.Stat()
	if err != nil || !privateRegular(identity) { return abort() }
	if file.Close() != nil { removePrivateOwned(name, identity); return "", nil, ErrIO }
	return name, identity, nil
}

func createPrivateArtifact(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) { return ErrConflict }
		return ErrIO
	}
	identity, err := file.Stat()
	if err != nil { _ = file.Close(); return ErrUnconfirmed }
	abort := func() error { _ = file.Close(); removePrivateOwned(path, identity); return ErrIO }
	if file.Chmod(0o600) != nil { return abort() }
	written, err := file.Write(body)
	if err != nil || written != len(body) || file.Sync() != nil { return abort() }
	if file.Close() != nil { return ErrUnconfirmed }
	current, err := os.Lstat(path)
	if err != nil || !privateRegular(current) || !os.SameFile(identity, current) || syncPrivateDirectory(filepath.Dir(path)) != nil { return ErrUnconfirmed }
	return nil
}

func artifactName(kind string) (string, bool) {
	switch kind {
	case "old": return "old.token", true
	case "new": return "new.token", true
	case "bundle": return "bundle.json", true
	default: return "", false
	}
}

func artifactValue(kind string, body []byte) (PrivateFile, error) {
	value, err := privateValue(body, kind != "bundle")
	if err != nil { return PrivateFile{}, err }
	if kind == "bundle" && !json.Valid(body) { return PrivateFile{}, ErrInvalidLifecycle }
	return value, nil
}
