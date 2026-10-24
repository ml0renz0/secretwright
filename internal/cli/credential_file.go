package cli

import (
	"errors"
	"io"
	"os"
)

var errCredentialFile = errors.New("could not reserve or write the private credential file; the output must not exist")

// Credential issuance reserves its final filename before contacting Vault.
// Unlike backup publication, that private file can be empty while a request is
// active. Never remove a path that somebody replaced after the reservation.
type credentialOutput struct {
	file      *os.File
	filename  string
	identity  os.FileInfo
	committed bool
}

func reserveCredentialOutput(filename string) (*credentialOutput, error) {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errCredentialFile
	}
	output := &credentialOutput{file: file, filename: filename}
	output.identity, err = file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, errCredentialFile
	}
	if err := file.Chmod(0o600); err != nil {
		output.abort()
		return nil, errCredentialFile
	}
	return output, nil
}

func (output *credentialOutput) ownsPath() bool {
	if output == nil || output.identity == nil || output.filename == "" {
		return false
	}
	current, err := os.Lstat(output.filename)
	return err == nil && current.Mode().IsRegular() && os.SameFile(output.identity, current)
}

func (output *credentialOutput) commit(encode func(io.Writer) error) error {
	if output == nil || output.file == nil || !output.ownsPath() {
		return errCredentialFile
	}
	if err := encode(output.file); err != nil {
		return errCredentialFile
	}
	if err := output.file.Sync(); err != nil {
		return errCredentialFile
	}
	if err := output.file.Close(); err != nil {
		output.file = nil
		return errCredentialFile
	}
	output.file = nil
	if !output.ownsPath() {
		return errCredentialFile
	}
	output.committed = true
	return nil
}

func (output *credentialOutput) abort() {
	if output == nil || output.committed {
		return
	}
	if output.file != nil {
		_ = output.file.Close()
		output.file = nil
	}
	if output.ownsPath() {
		_ = os.Remove(output.filename)
	}
	output.filename = ""
}

func encodeCredentialLine(value string) func(io.Writer) error {
	return func(output io.Writer) error {
		body := []byte(value + "\n")
		n, err := output.Write(body)
		if err != nil || n != len(body) {
			return errCredentialFile
		}
		return nil
	}
}
