package cli

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/ml0renz0/secretwright/internal/vault"
)

var errBackupFile = errors.New("could not publish the private backup file; the destination must not exist")

// Link installs a complete same-directory temporary file without replacing an
// existing file or following a destination symlink. No secret-derived path is
// ever passed to the filesystem; filename is explicitly selected by the user.
func writeBackupArchive(filename string, archive vault.Archive) error {
	file, err := os.CreateTemp(filepath.Dir(filename), ".secretwright-backup-*")
	if err != nil {
		return errBackupFile
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return errBackupFile
	}
	if err := vault.EncodeArchive(file, archive); err != nil {
		return errBackupFile
	}
	if err := file.Sync(); err != nil {
		return errBackupFile
	}
	if err := file.Close(); err != nil {
		return errBackupFile
	}
	if err := os.Link(temporary, filename); err != nil {
		return errBackupFile
	}
	return nil
}
