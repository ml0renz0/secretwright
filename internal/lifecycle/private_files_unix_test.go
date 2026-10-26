//go:build unix

package lifecycle_test

import (
	"os"
	"syscall"
	"testing"

	"github.com/ml0renz0/secretwright/internal/fileformat"
)

func TestRotationPublicationPreservesConsumerOwnerAndGroup(t *testing.T) {
	spec, path := ioFixture(t)
	store := ioOpen(t, spec, path, "", true)
	ioPrepare(t, store, spec, fileformat.YAML)
	receipt := ioAdvance(t, store)
	before, err := os.Stat(spec.Consumer.Path)
	if err != nil { t.Fatal("could not inspect initial consumer owner") }
	oldOwner, ok := before.Sys().(*syscall.Stat_t)
	if !ok { t.Fatal("Unix consumer metadata has no ownership information") }
	if store.Publish(receipt.OldDigest) != nil { t.Fatal("candidate publication failed") }
	after, err := os.Stat(spec.Consumer.Path)
	if err != nil { t.Fatal("could not inspect published consumer owner") }
	newOwner, ok := after.Sys().(*syscall.Stat_t)
	if !ok || oldOwner.Uid != newOwner.Uid || oldOwner.Gid != newOwner.Gid || after.Mode().Perm() != 0o600 {
		t.Error("atomic publication changed consumer ownership or private permissions")
	}
}
