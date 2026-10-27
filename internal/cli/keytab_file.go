package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ml0renz0/secretwright/internal/keytab"
)

var errKeytabFile = errors.New("could not read or publish a bounded private keytab file or regular policy file")
var errKeytabOutputConflict = errors.New("keytab output already exists or belongs to another writer")

func keytabFilePath(path string) bool {
	return path != "" && path != "-" && utf8.ValidString(path) && strings.IndexFunc(path, unicode.IsControl) < 0
}

func keytabPrivateFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func keytabSameFile(before, after os.FileInfo) bool {
	return before != nil && after != nil && before.Mode().IsRegular() && after.Mode().IsRegular() && os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

// Retain file evidence until native parsing has completed. No failed read or
// parser operation may return a partial private binary to its caller.
func readKeytabFileEvidence(path string, private bool) ([]byte, os.FileInfo, error) {
	if !keytabFilePath(path) {
		return nil, nil, errKeytabFile
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > keytab.MaxInputBytes || private && !keytabPrivateFile(before) {
		return nil, nil, errKeytabFile
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, errKeytabFile
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !keytabSameFile(before, opened) || private && !keytabPrivateFile(opened) {
		return nil, nil, errKeytabFile
	}
	body, err := io.ReadAll(io.LimitReader(file, keytab.MaxInputBytes+1))
	if err != nil || len(body) > keytab.MaxInputBytes {
		return nil, nil, errKeytabFile
	}
	after, statErr := file.Stat()
	current, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !keytabSameFile(opened, after) || !keytabSameFile(opened, current) || int64(len(body)) != after.Size() || private && (!keytabPrivateFile(after) || !keytabPrivateFile(current)) {
		return nil, nil, errKeytabFile
	}
	return body, current, nil
}

func keytabInputUnchanged(path string, evidence os.FileInfo, private bool) bool {
	current, err := os.Lstat(path)
	return err == nil && keytabSameFile(evidence, current) && (!private || keytabPrivateFile(current))
}

func readKeytabFile(path string) ([]byte, error) {
	body, evidence, err := readKeytabFileEvidence(path, true)
	if err != nil {
		return nil, errKeytabFile
	}
	if _, err := keytab.Inspect(bytes.NewReader(body)); err != nil || !keytabInputUnchanged(path, evidence, true) {
		return nil, errKeytabFile
	}
	return body, nil
}

func readKeytabPolicy(path string) (keytab.Policy, error) {
	body, evidence, err := readKeytabFileEvidence(path, false)
	if err != nil {
		return keytab.Policy{}, errKeytabFile
	}
	policy, err := keytab.LoadPolicy(bytes.NewReader(body))
	if err != nil || !keytabInputUnchanged(path, evidence, false) {
		return keytab.Policy{}, errKeytabFile
	}
	return policy, nil
}

// Reservation occurs before credentials or HTTP. The shared F06 writer remains
// unchanged; this wrapper enforces the keytab-specific name and mode contract.
func reserveKeytabOutput(path string) (*credentialOutput, error) {
	if !keytabFilePath(path) {
		return nil, errKeytabFile
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, errKeytabOutputConflict
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errKeytabFile
	}
	output, err := reserveCredentialOutput(path)
	if err != nil {
		if _, existsErr := os.Lstat(path); existsErr == nil {
			return nil, errKeytabOutputConflict
		}
		return nil, errKeytabFile
	}
	if !keytabOutputPrivate(output) {
		output.abort()
		return nil, errKeytabFile
	}
	return output, nil
}

func keytabOutputPrivate(output *credentialOutput) bool {
	if output == nil || !output.ownsPath() {
		return false
	}
	info, err := os.Lstat(output.filename)
	return err == nil && keytabPrivateFile(info)
}

func commitKeytabOutput(output *credentialOutput, body []byte) error {
	if !keytabOutputPrivate(output) || len(body) > keytab.MaxInputBytes {
		return errKeytabFile
	}
	if _, err := keytab.Inspect(bytes.NewReader(body)); err != nil {
		return errKeytabFile
	}
	if !keytabOutputPrivate(output) {
		return errKeytabFile
	}
	err := output.commit(func(writer io.Writer) error {
		written, err := writer.Write(body)
		if err != nil || written != len(body) {
			return errKeytabFile
		}
		return nil
	})
	if err != nil || !keytabOutputPrivate(output) {
		return errKeytabFile
	}
	return nil
}
