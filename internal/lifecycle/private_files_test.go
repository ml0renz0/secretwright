package lifecycle

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConstructorCleanupRemovesOnlyItsOwnLockDespiteModeChanges(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		name := "same-inode-mode-change"
		if replacement {
			name = "foreign-inode"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "receipt")
			lock, err := os.OpenFile(path+".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				t.Fatal("could not create constructor lock fixture")
			}
			identity, err := lock.Stat()
			if err != nil {
				_ = lock.Close()
				t.Fatal("could not identify constructor lock fixture")
			}
			store := &Store{path: path, lock: lock, lockInfo: identity, writable: true}
			if replacement {
				if os.Remove(path+".lock") != nil || os.WriteFile(path+".lock", []byte("foreign-writer"), 0o600) != nil {
					t.Fatal("could not replace constructor lock fixture")
				}
			} else if os.Chmod(path+".lock", 0o400) != nil {
				t.Fatal("could not change constructor lock permissions")
			}
			store.abortOpen()
			if replacement {
				body, err := os.ReadFile(path + ".lock")
				if err != nil || string(body) != "foreign-writer" {
					t.Error("constructor cleanup removed another writer's inode")
				}
			} else if _, err := os.Lstat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
				t.Error("constructor cleanup left its own chmodded lock")
			}
		})
	}
}

func TestFinalLocalPreflightRejectsProofChangesBeforeCredentialLoading(t *testing.T) {
	for _, changed := range []string{"consumer", "receipt", "lock"} {
		t.Run(changed, func(t *testing.T) {
			directory := t.TempDir()
			consumer := filepath.Join(directory, "consumer.token")
			path := filepath.Join(directory, "receipt.yaml")
			if os.WriteFile(consumer, []byte("private-old-token\n"), 0o600) != nil {
				t.Fatal("could not create local preflight consumer")
			}
			spec := Spec{
				APIVersion: APIVersion,
				Name:       "payments-api",
				Provider:   ProviderSpec{Kind: "approle", AuthMount: "approle", Role: "payments-api"},
				Consumer:   ConsumerSpec{Kind: "token-file", Path: consumer},
				Verify:     VerifySpec{Kind: "kv-read", Mount: "secret", KVVersion: 2, Path: "/secret/payments/health"},
				Policy:     PolicySpec{RotateBelow: "5m", MinimumNewTTL: "10m"},
			}
			store, err := Open(spec, path, "", true)
			if err != nil {
				t.Fatal("could not open local preflight fixture")
			}
			defer store.Close()
			switch changed {
			case "consumer":
				if os.WriteFile(consumer, []byte("private-foreign-token\n"), 0o600) != nil {
					t.Fatal("could not change local preflight consumer")
				}
			case "receipt":
				if os.WriteFile(path, []byte("foreign-receipt"), 0o600) != nil {
					t.Fatal("could not create local preflight receipt conflict")
				}
			case "lock":
				if os.Remove(path+".lock") != nil || os.WriteFile(path+".lock", []byte("foreign-writer"), 0o600) != nil {
					t.Fatal("could not change local preflight lock")
				}
			}
			if !errors.Is(store.localPreflight(), ErrConflict) {
				t.Error("final local preflight accepted changed local proof")
			}
		})
	}
}
