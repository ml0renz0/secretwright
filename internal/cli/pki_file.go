package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ml0renz0/secretwright/internal/pki"
)

const pkiDocumentLimit = 1 << 20

var errPKIFile = errors.New("could not read a bounded regular PKI input file with the required permissions")

func pkiPrivateMode(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func samePKIFile(before, after os.FileInfo) bool {
	return before != nil && after != nil && before.Mode().IsRegular() && after.Mode().IsRegular() && os.SameFile(before, after) && before.Mode() == after.Mode() && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

// Keep the inode, mode, size and modification-time evidence until parsing has
// finished. A certificate file may turn out to contain a private identity key.
func readPKIFileEvidence(path string, private bool, limit int64) ([]byte, os.FileInfo, error) {
	if path == "" || path == "-" || !utf8.ValidString(path) || strings.IndexFunc(path, unicode.IsControl) >= 0 || limit <= 0 || limit > pkiDocumentLimit {
		return nil, nil, errPKIFile
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit || private && !pkiPrivateMode(before) {
		return nil, nil, errPKIFile
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, errPKIFile
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !samePKIFile(before, opened) || private && !pkiPrivateMode(opened) {
		return nil, nil, errPKIFile
	}
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, nil, errPKIFile
	}
	after, statErr := file.Stat()
	current, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !samePKIFile(opened, after) || !samePKIFile(opened, current) || int64(len(body)) != after.Size() || private && (!pkiPrivateMode(after) || !pkiPrivateMode(current)) {
		return nil, nil, errPKIFile
	}
	return body, current, nil
}

// readPKIFile returns exact bytes without interpreting their encoding. The
// native PEM/configuration parser determines the allowed document profile.
func readPKIFile(path string, private bool, limit int64) ([]byte, error) {
	body, _, err := readPKIFileEvidence(path, private, limit)
	return body, err
}

func pkiInputUnchanged(path string, evidence os.FileInfo, private bool) bool {
	current, err := os.Lstat(path)
	return err == nil && samePKIFile(evidence, current) && (!private || pkiPrivateMode(current))
}

func readPKICertificates(path string) ([]byte, error) {
	body, evidence, err := readPKIFileEvidence(path, false, pkiDocumentLimit)
	if err != nil {
		return nil, errPKIFile
	}
	report, err := pki.InspectCertificates(bytes.NewReader(body), time.Now().UTC())
	if err != nil || report.ContainsPrivateKey && !pkiPrivateMode(evidence) || !pkiInputUnchanged(path, evidence, report.ContainsPrivateKey) {
		return nil, errPKIFile
	}
	return body, nil
}

func readPKIKey(path string) ([]byte, error) {
	body, evidence, err := readPKIFileEvidence(path, true, pkiDocumentLimit)
	if err != nil {
		return nil, errPKIFile
	}
	if _, err := pki.InspectPrivateKey(bytes.NewReader(body)); err != nil || !pkiInputUnchanged(path, evidence, true) {
		return nil, errPKIFile
	}
	return body, nil
}

func readPKICSR(path string) ([]byte, error) {
	body, evidence, err := readPKIFileEvidence(path, false, pkiDocumentLimit)
	if err != nil {
		return nil, errPKIFile
	}
	if _, err := pki.InspectCSR(bytes.NewReader(body)); err != nil || !pkiInputUnchanged(path, evidence, false) {
		return nil, errPKIFile
	}
	return body, nil
}
