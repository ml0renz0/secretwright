package lifecycle_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/fileformat"
	"github.com/ml0renz0/secretwright/internal/lifecycle"
	"github.com/ml0renz0/secretwright/internal/managedstate"
	"github.com/ml0renz0/secretwright/internal/vault"
)

const ioOldToken = "private-f10-old-token"
const ioNewToken = "private-f10-new-token"

func ioDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func ioFixture(t *testing.T) (lifecycle.Spec, string) {
	t.Helper()
	directory := t.TempDir()
	consumer := filepath.Join(directory, "consumer.token")
	if err := os.WriteFile(consumer, []byte(ioOldToken+"\n"), 0o600); err != nil {
		t.Fatal("could not prepare private consumer fixture")
	}
	spec := lifecycle.Spec{
		APIVersion: "secretwright/lifecycle/v1", Name: "payments-api",
		Provider: lifecycle.ProviderSpec{Kind: "approle", AuthMount: "approle", Role: "payments-api"},
		Consumer: lifecycle.ConsumerSpec{Kind: "token-file", Path: consumer},
		Verify:   lifecycle.VerifySpec{Kind: "kv-read", Mount: "secret", KVVersion: 2, Path: "/secret/payments/health"},
		Policy:   lifecycle.PolicySpec{RotateBelow: "5m", MinimumNewTTL: "10m"},
	}
	spec, err := lifecycle.ValidateSpec(spec)
	if err != nil {
		t.Fatal("valid I/O lifecycle fixture was rejected")
	}
	return spec, filepath.Join(directory, "rotation.yaml")
}

func ioPrepared(spec lifecycle.Spec, format fileformat.Format) lifecycle.Receipt {
	return lifecycle.Receipt{
		APIVersion: "secretwright/rotation/v1", Name: spec.Name,
		ConfigSHA256: lifecycle.SpecHash(spec),
		Target:       managedstate.Target{AddressSHA256: strings.Repeat("a", 64), ClusterID: "11111111-1111-4111-8111-111111111111", Namespace: "team"},
		Revision:     1, Generation: strings.Repeat("1", 32), Phase: "prepared",
		RoleIdentity: strings.Repeat("b", 64), OldDigest: ioDigest([]byte(ioOldToken + "\n")),
		EntityID: "22222222-2222-4222-8222-222222222222", Format: format,
	}
}

func ioOpen(t *testing.T, spec lifecycle.Spec, path string, format fileformat.Format, writable bool) *lifecycle.Store {
	t.Helper()
	store, err := lifecycle.Open(spec, path, format, writable)
	if err != nil {
		t.Fatal("could not open valid private rotation store")
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func ioPrepare(t *testing.T, store *lifecycle.Store, spec lifecycle.Spec, format fileformat.Format) lifecycle.Receipt {
	t.Helper()
	old, err := store.Consumer()
	if err != nil {
		t.Fatal("could not read original consumer")
	}
	receipt := ioPrepared(spec, format)
	if err := store.Prepare(receipt, old); err != nil {
		t.Fatal("could not prepare first rotation checkpoint")
	}
	return receipt
}

func ioRequireMode(t *testing.T, path string, want os.FileMode, directory bool) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != want || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) {
		t.Fatal("rotation artifact lost its required private type or permissions")
	}
}

func ioRead(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("could not read rotation fixture")
	}
	return body
}

func ioNoArtifact(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("read-only or rejected operation created an artifact")
	}
}

func ioStaticError(t *testing.T, err error, paths ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("unsafe private-file operation succeeded")
	}
	for _, value := range append([]string{ioOldToken, ioNewToken, "private-bundle-secret"}, paths...) {
		if value != "" && strings.Contains(err.Error(), value) {
			t.Error("private-file error exposed credential data or a path")
		}
	}
}

func ioAdvance(t *testing.T, store *lifecycle.Store) lifecycle.Receipt {
	t.Helper()
	bundle := []byte(`{"role_id":"private-role-id","secret_id":"private-bundle-secret"}` + "\n")
	if store.Put("bundle", bundle) != nil || store.Put("new", []byte(ioNewToken+"\n")) != nil {
		t.Fatal("could not persist private candidate artifacts")
	}
	receipt := store.Snapshot()
	receipt.BundleDigest = ioDigest(bundle)
	for _, phase := range []string{"secret_issued", "pending_login", "candidate_ready", "verified", "pending_publish"} {
		receipt.Revision++
		receipt.Phase = phase
		if phase == "candidate_ready" {
			receipt.NewDigest = ioDigest([]byte(ioNewToken + "\n"))
		}
		if store.Save(receipt) != nil {
			t.Fatal("could not advance valid rotation checkpoint")
		}
	}
	return receipt
}

func TestRotationReadOnlyOpenCreatesNothingAndDoesNotTouchForeignLock(t *testing.T) {
	spec, path := ioFixture(t)
	lock := path + ".lock"
	if err := os.WriteFile(lock, []byte("private-foreign-writer"), 0o600); err != nil {
		t.Fatal("could not create foreign lock fixture")
	}
	before, _ := os.Lstat(lock)
	store := ioOpen(t, spec, path, "", false)
	if got := store.Snapshot(); got.APIVersion != "" || got.Revision != 0 || got.Format != fileformat.YAML {
		t.Error("new read-only store did not retain the default YAML selection")
	}
	consumer, err := store.Consumer()
	if err != nil || consumer.Token != ioOldToken || !bytes.Equal(consumer.Data, []byte(ioOldToken+"\n")) || consumer.Digest != ioDigest(consumer.Data) {
		t.Error("consumer read lost exact bytes, normalized token, or raw-byte proof")
	}
	if !errors.Is(store.Prepare(ioPrepared(spec, fileformat.YAML), consumer), lifecycle.ErrConflict) || !errors.Is(store.Put("new", []byte(ioNewToken+"\n")), lifecycle.ErrConflict) {
		t.Error("read-only session accepted private writes")
	}
	if store.Close() != nil {
		t.Error("read-only close failed")
	}
	after, _ := os.Lstat(lock)
	if after == nil || !os.SameFile(before, after) || string(ioRead(t, lock)) != "private-foreign-writer" {
		t.Error("read-only store touched another writer's lock")
	}
	ioNoArtifact(t, path)
	ioNoArtifact(t, path+".d")
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 2 {
		t.Error("read-only store left unexpected temporary artifacts")
	}
}

func TestRotationPrivateReaderRejectsUnsafeFilesWithoutEcho(t *testing.T) {
	for _, fixture := range []struct {
		name string
		body []byte
		mode os.FileMode
	}{
		{"public", []byte(ioOldToken), 0o644},
		{"empty", nil, 0o600},
		{"multiple", []byte(ioOldToken + " " + ioNewToken), 0o600},
		{"invalid-utf8", []byte{0xff, 0xfe}, 0o600},
		{"oversized", bytes.Repeat([]byte("x"), (64<<10)+1), 0o600},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-token-file")
			if os.WriteFile(path, fixture.body, fixture.mode) != nil {
				t.Fatal("could not prepare private reader fixture")
			}
			if os.Chmod(path, fixture.mode) != nil {
				t.Fatal("could not set private reader fixture permissions")
			}
			value, err := lifecycle.ReadPrivate(path)
			ioStaticError(t, err, path)
			if !reflect.DeepEqual(value, lifecycle.PrivateFile{}) {
				t.Error("rejected private file returned partial credential data")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "private-link")
	target := path + "-target"
	if os.WriteFile(target, []byte(ioOldToken+"\n"), 0o600) != nil || os.Symlink(target, path) != nil {
		t.Fatal("could not prepare final-symlink fixture")
	}
	_, err := lifecycle.ReadPrivate(path)
	ioStaticError(t, err, path, target)
	_, err = lifecycle.ReadPrivate(filepath.Dir(path))
	ioStaticError(t, err, filepath.Dir(path))
}

func TestRotationOpenValidatesLocalConsumerBeforeLeavingAnyArtifacts(t *testing.T) {
	for _, fixture := range []string{"missing", "public", "symlink", "directory", "invalid-token"} {
		t.Run(fixture, func(t *testing.T) {
			spec, path := ioFixture(t)
			switch fixture {
			case "missing":
				if os.Remove(spec.Consumer.Path) != nil {
					t.Fatal("fixture removal failed")
				}
			case "public":
				if os.Chmod(spec.Consumer.Path, 0o644) != nil {
					t.Fatal("fixture permission failed")
				}
			case "symlink":
				target := spec.Consumer.Path + ".target"
				if os.Rename(spec.Consumer.Path, target) != nil || os.Symlink(target, spec.Consumer.Path) != nil {
					t.Fatal("fixture symlink failed")
				}
			case "directory":
				if os.Remove(spec.Consumer.Path) != nil || os.Mkdir(spec.Consumer.Path, 0o700) != nil {
					t.Fatal("fixture directory failed")
				}
			case "invalid-token":
				if os.WriteFile(spec.Consumer.Path, []byte(ioOldToken+" "+ioNewToken), 0o600) != nil {
					t.Fatal("fixture token failed")
				}
			}
			store, err := lifecycle.Open(spec, path, "", true)
			ioStaticError(t, err, path, spec.Consumer.Path)
			if store != nil {
				_ = store.Close()
				t.Error("rejected consumer returned a usable store")
			}
			ioNoArtifact(t, path)
			ioNoArtifact(t, path+".lock")
			ioNoArtifact(t, path+".d")
		})
	}
	spec, path := ioFixture(t)
	store, err := lifecycle.Open(spec, path, fileformat.Format("private-format"), true)
	ioStaticError(t, err, path)
	if store != nil {
		_ = store.Close()
		t.Error("invalid output format returned a usable store")
	}
	ioNoArtifact(t, path)
	ioNoArtifact(t, path+".lock")
	ioNoArtifact(t, path+".d")
}

func TestRotationPreparePublishesPrivateYAMLReceiptBeforeCandidate(t *testing.T) {
	spec, path := ioFixture(t)
	store := ioOpen(t, spec, path, "", true)
	ioRequireMode(t, path+".lock", 0o600, false)
	ioNoArtifact(t, path)
	receipt := ioPrepare(t, store, spec, fileformat.YAML)
	if !reflect.DeepEqual(store.Snapshot(), receipt) {
		t.Error("prepared checkpoint differs from its snapshot")
	}
	body := ioRead(t, path)
	if json.Valid(body) || !bytes.Contains(body, []byte("api_version:")) || body[len(body)-1] != '\n' {
		t.Error("rotation receipt did not default to complete YAML with a final newline")
	}
	decoded, err := lifecycle.DecodeReceipt(bytes.NewReader(body))
	if err != nil || !reflect.DeepEqual(decoded, receipt) {
		t.Error("published receipt cannot be read back exactly")
	}
	for _, secret := range []string{ioOldToken, ioNewToken, spec.Consumer.Path, "private-role-id", "private-bundle-secret"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Error("rotation receipt leaked private values or consumer path")
		}
	}
	ioRequireMode(t, path, 0o600, false)
	ioRequireMode(t, path+".d", 0o700, true)
	generation := filepath.Join(path+".d", receipt.Generation)
	ioRequireMode(t, generation, 0o700, true)
	ioRequireMode(t, filepath.Join(generation, "old.token"), 0o600, false)
	if !bytes.Equal(ioRead(t, filepath.Join(generation, "old.token")), []byte(ioOldToken+"\n")) {
		t.Error("old-token backup changed exact consumer bytes")
	}
	ioNoArtifact(t, filepath.Join(generation, "new.token"))
	ioNoArtifact(t, filepath.Join(generation, "bundle.json"))
	if store.Close() != nil {
		t.Error("owned private lock could not be closed")
	}
	ioNoArtifact(t, path+".lock")
	ioRequireMode(t, filepath.Join(generation, "old.token"), 0o600, false)
}

func TestRotationExistingEncodingAndBindingArePreserved(t *testing.T) {
	spec, path := ioFixture(t)
	store := ioOpen(t, spec, path, fileformat.JSON, true)
	ioPrepare(t, store, spec, fileformat.JSON)
	if !json.Valid(ioRead(t, path)) || store.Close() != nil {
		t.Fatal("explicit JSON receipt could not be persisted")
	}
	store = ioOpen(t, spec, path, "", true)
	if store.Snapshot().Format != fileformat.JSON || store.Close() != nil {
		t.Error("existing JSON encoding was not preserved on reopen")
	}
	if _, err := lifecycle.Open(spec, path, fileformat.YAML, true); !errors.Is(err, lifecycle.ErrConflict) {
		t.Error("an explicit encoding change was allowed for an existing receipt")
	}
	ioNoArtifact(t, path+".lock")
	foreign := spec
	foreign.Name = "foreign-app"
	if _, err := lifecycle.Open(foreign, path, "", true); !errors.Is(err, lifecycle.ErrConflict) {
		t.Error("receipt belonging to a different lifecycle was accepted")
	}
	ioNoArtifact(t, path+".lock")
}

func TestRotationPrivateArtifactsUseFixedExclusiveNamesAndOpaqueBytes(t *testing.T) {
	spec, path := ioFixture(t)
	store := ioOpen(t, spec, path, "", true)
	receipt := ioPrepare(t, store, spec, fileformat.YAML)
	for _, item := range []struct {
		kind, name string
		body       []byte
	}{
		{"new", "new.token", []byte(ioNewToken + "\n")},
		{"bundle", "bundle.json", []byte("{\"secret_id\":\"private-bundle-secret\"}\n")},
	} {
		if err := store.Put(item.kind, item.body); err != nil {
			t.Fatal("could not create fixed private artifact")
		}
		got, err := store.Load(item.kind)
		if err != nil || !bytes.Equal(got.Data, item.body) || got.Digest != ioDigest(item.body) || (item.kind == "bundle" && got.Token != "") || (item.kind == "new" && got.Token != ioNewToken) {
			t.Error("artifact reader changed opaque bytes or credential semantics")
		}
		ioStaticError(t, store.Put(item.kind, []byte("replacement")), path)
		if !bytes.Equal(ioRead(t, filepath.Join(path+".d", receipt.Generation, item.name)), item.body) {
			t.Error("exclusive artifact write replaced an existing credential")
		}
		ioRequireMode(t, filepath.Join(path+".d", receipt.Generation, item.name), 0o600, false)
	}
	for _, kind := range []string{"", "../private-escape", "new.token", "/tmp/private-escape", "generation/new"} {
		ioStaticError(t, store.Put(kind, []byte(ioNewToken)), path)
		_, err := store.Load(kind)
		ioStaticError(t, err, path)
	}
	encoded, _ := json.Marshal(lifecycle.PrivateFile{Data: []byte(ioOldToken), Token: ioOldToken, Digest: "private-proof"})
	if string(encoded) != "{}" {
		t.Error("private artifact fields became JSON-serializable")
	}
}

func TestRotationPublishAtomicallyChangesConsumerAndRetainsOldBackup(t *testing.T) {
	spec, path := ioFixture(t)
	store := ioOpen(t, spec, path, "", true)
	ioPrepare(t, store, spec, fileformat.YAML)
	receipt := ioAdvance(t, store)
	before, _ := os.Lstat(spec.Consumer.Path)
	if err := store.Publish(receipt.OldDigest); err != nil {
		t.Fatal("verified candidate could not be published")
	}
	after, _ := os.Lstat(spec.Consumer.Path)
	if before == nil || after == nil || os.SameFile(before, after) || !bytes.Equal(ioRead(t, spec.Consumer.Path), []byte(ioNewToken+"\n")) {
		t.Error("consumer publication was not an atomic complete replacement")
	}
	ioRequireMode(t, spec.Consumer.Path, 0o600, false)
	if !bytes.Equal(ioRead(t, filepath.Join(path+".d", receipt.Generation, "old.token")), []byte(ioOldToken+"\n")) {
		t.Error("consumer publication changed the retained old credential")
	}
	consumer, err := store.Consumer()
	if err != nil || consumer.Token != ioNewToken || consumer.Digest != receipt.NewDigest {
		t.Error("consumer read did not confirm the newly published proof")
	}
	if store.Snapshot().Phase != "pending_publish" {
		t.Error("file adapter claimed the engine's post-publication checkpoint")
	}
}

func TestRotationPublishRefusesExternalConsumerChangesWithoutClobber(t *testing.T) {
	for _, change := range []string{"content", "same-content-inode", "mode", "symlink", "candidate-content"} {
		t.Run(change, func(t *testing.T) {
			spec, path := ioFixture(t)
			store := ioOpen(t, spec, path, "", true)
			ioPrepare(t, store, spec, fileformat.YAML)
			receipt := ioAdvance(t, store)
			switch change {
			case "content":
				if os.WriteFile(spec.Consumer.Path, []byte("private-foreign-token\n"), 0o600) != nil {
					t.Fatal("fixture write failed")
				}
			case "same-content-inode":
				replacement := spec.Consumer.Path + ".replacement"
				if os.WriteFile(replacement, []byte(ioOldToken+"\n"), 0o600) != nil || os.Rename(replacement, spec.Consumer.Path) != nil {
					t.Fatal("fixture replacement failed")
				}
			case "mode":
				if os.Chmod(spec.Consumer.Path, 0o644) != nil {
					t.Fatal("fixture mode change failed")
				}
			case "symlink":
				target := spec.Consumer.Path + ".foreign"
				if os.WriteFile(target, []byte("private-foreign-token\n"), 0o600) != nil || os.Remove(spec.Consumer.Path) != nil || os.Symlink(target, spec.Consumer.Path) != nil {
					t.Fatal("fixture symlink failed")
				}
			case "candidate-content":
				if os.WriteFile(filepath.Join(path+".d", receipt.Generation, "new.token"), []byte("private-foreign-token\n"), 0o600) != nil {
					t.Fatal("candidate fixture change failed")
				}
			}
			before := ioRead(t, spec.Consumer.Path)
			info, _ := os.Lstat(spec.Consumer.Path)
			err := store.Publish(receipt.OldDigest)
			ioStaticError(t, err, path, spec.Consumer.Path)
			if !errors.Is(err, lifecycle.ErrConflict) {
				t.Error("external credential change did not produce a conflict")
			}
			after, _ := os.Lstat(spec.Consumer.Path)
			if !bytes.Equal(before, ioRead(t, spec.Consumer.Path)) || info == nil || after == nil || !os.SameFile(info, after) || info.Mode() != after.Mode() {
				t.Error("rejected publication clobbered a consumer owned by another writer")
			}
		})
	}
}

func TestRotationSaveRefusesStaleReceiptLockOrBinding(t *testing.T) {
	for _, change := range []string{"receipt-comment", "receipt-inode", "receipt-mode", "receipt-symlink", "lock-inode", "binding", "revision", "generation", "old-proof", "format"} {
		t.Run(change, func(t *testing.T) {
			spec, path := ioFixture(t)
			store := ioOpen(t, spec, path, "", true)
			ioPrepare(t, store, spec, fileformat.YAML)
			next := store.Snapshot()
			next.Revision++
			next.Phase = "aborted"
			switch change {
			case "receipt-comment":
				body := append(ioRead(t, path), []byte("# external edit\n")...)
				if os.WriteFile(path, body, 0o600) != nil {
					t.Fatal("fixture write failed")
				}
			case "receipt-inode":
				replacement := path + ".replacement"
				if os.WriteFile(replacement, ioRead(t, path), 0o600) != nil || os.Rename(replacement, path) != nil {
					t.Fatal("fixture replacement failed")
				}
			case "receipt-mode":
				if os.Chmod(path, 0o644) != nil {
					t.Fatal("fixture mode failed")
				}
			case "receipt-symlink":
				foreign := path + ".foreign"
				if os.WriteFile(foreign, ioRead(t, path), 0o600) != nil || os.Remove(path) != nil || os.Symlink(foreign, path) != nil {
					t.Fatal("fixture link failed")
				}
			case "lock-inode":
				if os.Remove(path+".lock") != nil || os.WriteFile(path+".lock", []byte("foreign"), 0o600) != nil {
					t.Fatal("fixture lock failed")
				}
			case "binding":
				next.Target.Namespace = "foreign"
			case "revision":
				next.Revision++
			case "generation":
				next.Generation = strings.Repeat("2", 32)
			case "old-proof":
				next.OldDigest = strings.Repeat("c", 64)
			case "format":
				next.Format = fileformat.JSON
			}
			before := ioRead(t, path)
			err := store.Save(next)
			ioStaticError(t, err, path)
			if !errors.Is(err, lifecycle.ErrConflict) {
				t.Error("stale receipt or binding change did not produce a conflict")
			}
			if !bytes.Equal(before, ioRead(t, path)) {
				t.Error("rejected checkpoint replaced external receipt contents")
			}
			if change == "lock-inode" {
				_ = store.Close()
				if string(ioRead(t, path+".lock")) != "foreign" {
					t.Error("Close removed somebody else's replacement lock")
				}
			}
		})
	}
}

func TestRotationExclusiveLockAndTerminalGenerationRules(t *testing.T) {
	spec, path := ioFixture(t)
	store := ioOpen(t, spec, path, "", true)
	if _, err := lifecycle.Open(spec, path, "", true); !errors.Is(err, lifecycle.ErrConflict) {
		t.Error("second writer stole an active private lock")
	}
	first := ioPrepare(t, store, spec, fileformat.YAML)
	old, _ := store.Consumer()
	next := first
	next.Generation = strings.Repeat("2", 32)
	next.Revision++
	if err := store.Prepare(next, old); !errors.Is(err, lifecycle.ErrConflict) {
		t.Error("an unfinished generation was replaced")
	}
	aborted := first
	aborted.Phase = "aborted"
	aborted.Revision++
	if store.Save(aborted) != nil {
		t.Fatal("could not persist explicit abandonment checkpoint")
	}
	next.Revision = aborted.Revision + 1
	if store.Prepare(next, old) != nil || store.Snapshot().Generation != next.Generation || store.Snapshot().Revision != next.Revision {
		t.Error("terminal receipt could not start a distinct monotonic generation")
	}
	ioRequireMode(t, filepath.Join(path+".d", first.Generation, "old.token"), 0o600, false)
	ioRequireMode(t, filepath.Join(path+".d", next.Generation, "old.token"), 0o600, false)
}

func TestRotationPrepareRefusesSymlinkOrPublicArtifactDirectories(t *testing.T) {
	for _, fixture := range []string{"symlink-parent", "public-parent", "symlink-generation", "public-generation"} {
		t.Run(fixture, func(t *testing.T) {
			spec, path := ioFixture(t)
			store := ioOpen(t, spec, path, "", true)
			receipt := ioPrepared(spec, fileformat.YAML)
			root := path + ".d"
			generation := filepath.Join(root, receipt.Generation)
			foreign := filepath.Join(filepath.Dir(path), "foreign-artifacts")
			if os.Mkdir(foreign, 0o700) != nil {
				t.Fatal("fixture directory failed")
			}
			switch fixture {
			case "symlink-parent":
				if os.Symlink(foreign, root) != nil {
					t.Fatal("fixture symlink failed")
				}
			case "public-parent":
				if os.Mkdir(root, 0o755) != nil {
					t.Fatal("fixture directory failed")
				}
				if os.Chmod(root, 0o755) != nil {
					t.Fatal("fixture directory mode failed")
				}
			case "symlink-generation":
				if os.Mkdir(root, 0o700) != nil || os.Symlink(foreign, generation) != nil {
					t.Fatal("fixture symlink failed")
				}
			case "public-generation":
				if os.Mkdir(root, 0o700) != nil || os.Mkdir(generation, 0o755) != nil {
					t.Fatal("fixture directory failed")
				}
				if os.Chmod(generation, 0o755) != nil {
					t.Fatal("fixture directory mode failed")
				}
			}
			old, _ := store.Consumer()
			ioStaticError(t, store.Prepare(receipt, old), path, foreign)
			ioNoArtifact(t, path)
			entries, _ := os.ReadDir(foreign)
			if len(entries) != 0 {
				t.Error("private generation write followed an external directory")
			}
		})
	}
}

func TestRotationSaveRejectsConsumerChangedBeforeRetirementCheckpoint(t *testing.T) {
	for _, change := range []string{"content", "inode", "mode", "symlink"} {
		t.Run(change, func(t *testing.T) {
			spec, path := ioFixture(t)
			store := ioOpen(t, spec, path, "", true)
			ioPrepare(t, store, spec, fileformat.YAML)
			receipt := ioAdvance(t, store)
			if store.Publish(receipt.OldDigest) != nil {
				t.Fatal("could not publish retirement fixture")
			}
			receipt.Revision++
			receipt.Phase = "published"
			if store.Save(receipt) != nil {
				t.Fatal("could not checkpoint retirement fixture")
			}
			switch change {
			case "content":
				if os.WriteFile(spec.Consumer.Path, []byte(ioOldToken+"\n"), 0o600) != nil {
					t.Fatal("could not change consumer fixture")
				}
			case "inode":
				replacement := spec.Consumer.Path + ".replacement"
				if os.WriteFile(replacement, []byte(ioNewToken+"\n"), 0o600) != nil || os.Rename(replacement, spec.Consumer.Path) != nil {
					t.Fatal("could not replace consumer fixture")
				}
			case "mode":
				if os.Chmod(spec.Consumer.Path, 0o644) != nil {
					t.Fatal("could not change consumer mode")
				}
			case "symlink":
				target := spec.Consumer.Path + ".target"
				if os.Rename(spec.Consumer.Path, target) != nil || os.Symlink(target, spec.Consumer.Path) != nil {
					t.Fatal("could not replace consumer with a symlink")
				}
			}
			before := ioRead(t, path)
			receipt.Revision++
			receipt.Phase = "pending_retire"
			if !errors.Is(store.Save(receipt), lifecycle.ErrConflict) || !bytes.Equal(before, ioRead(t, path)) || store.Snapshot().Phase != "published" {
				t.Error("changed consumer was accepted by the pre-revocation checkpoint")
			}
		})
	}
}

func TestRotationTerminalArtifactsCanBeRemovedBeforeTheNextGeneration(t *testing.T) {
	for _, phase := range []string{"aborted", "retired"} {
		for _, removed := range []string{"files", "generation", "root"} {
			t.Run(phase+"/"+removed, func(t *testing.T) {
				spec, path := ioFixture(t)
				store := ioOpen(t, spec, path, "", true)
				receipt := ioPrepare(t, store, spec, fileformat.YAML)
				if phase == "retired" {
					receipt = ioAdvance(t, store)
					if store.Publish(receipt.OldDigest) != nil {
						t.Fatal("could not publish terminal fixture")
					}
					for _, checkpoint := range []string{"published", "pending_retire", "retired"} {
						receipt.Revision++
						receipt.Phase = checkpoint
						if store.Save(receipt) != nil {
							t.Fatal("could not checkpoint terminal fixture")
						}
					}
				} else {
					receipt.Revision++
					receipt.Phase = "aborted"
					if store.Save(receipt) != nil {
						t.Fatal("could not abandon fixture")
					}
				}
				if store.Close() != nil {
					t.Fatal("could not release terminal fixture")
				}
				generation := filepath.Join(path+".d", receipt.Generation)
				switch removed {
				case "files":
					for _, name := range []string{"old.token", "new.token", "bundle.json"} {
						if err := os.Remove(filepath.Join(generation, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
							t.Fatal("could not remove terminal artifact")
						}
					}
				case "generation":
					if os.RemoveAll(generation) != nil {
						t.Fatal("could not remove terminal generation")
					}
				case "root":
					if os.RemoveAll(path+".d") != nil {
						t.Fatal("could not remove terminal artifact root")
					}
				}
				store = ioOpen(t, spec, path, "", true)
				if _, err := store.Load("old"); !errors.Is(err, vault.ErrNotFound) {
					t.Error("removed terminal artifact was not reported as absent")
				}
				old, err := store.Consumer()
				if err != nil {
					t.Fatal("could not read current terminal consumer")
				}
				next := ioPrepared(spec, fileformat.YAML)
				next.Generation = strings.Repeat("2", 32)
				next.Revision = receipt.Revision + 1
				next.OldDigest = old.Digest
				if store.Prepare(next, old) != nil || store.Snapshot().Generation != next.Generation {
					t.Error("manual terminal retention cleanup prevented a new generation")
				}
			})
		}
	}
}

func TestRotationTerminalArtifactsStillRequirePrivateRegularFiles(t *testing.T) {
	for _, fixture := range []string{"public-file", "symlink-file", "public-root", "symlink-root", "public-generation", "symlink-generation"} {
		t.Run(fixture, func(t *testing.T) {
			spec, path := ioFixture(t)
			store := ioOpen(t, spec, path, "", true)
			receipt := ioPrepare(t, store, spec, fileformat.YAML)
			receipt.Revision++
			receipt.Phase = "aborted"
			if store.Save(receipt) != nil || store.Close() != nil {
				t.Fatal("could not checkpoint terminal fixture")
			}
			root := path + ".d"
			generation := filepath.Join(root, receipt.Generation)
			old := filepath.Join(generation, "old.token")
			switch fixture {
			case "public-file":
				if os.Chmod(old, 0o644) != nil {
					t.Fatal("could not change artifact mode")
				}
			case "public-root":
				if os.Chmod(root, 0o755) != nil {
					t.Fatal("could not change root mode")
				}
			case "public-generation":
				if os.Chmod(generation, 0o755) != nil {
					t.Fatal("could not change generation mode")
				}
			default:
				changed := old
				if fixture == "symlink-root" {
					changed = root
				} else if fixture == "symlink-generation" {
					changed = generation
				}
				target := changed + ".target"
				if os.Rename(changed, target) != nil || os.Symlink(target, changed) != nil {
					t.Fatal("could not replace terminal artifact with a symlink")
				}
			}
			opened, err := lifecycle.Open(spec, path, "", true)
			if err == nil || opened != nil {
				if opened != nil {
					_ = opened.Close()
				}
				t.Error("terminal cleanup exception accepted unsafe existing artifacts")
			}
			ioNoArtifact(t, path+".lock")
		})
	}
}

func TestRotationMissingArtifactDoesNotConflateUnsafeOrUnreadableFiles(t *testing.T) {
	spec, path := ioFixture(t)
	store := ioOpen(t, spec, path, "", true)
	receipt := ioPrepare(t, store, spec, fileformat.YAML)
	if _, err := store.Load("new"); !errors.Is(err, vault.ErrNotFound) {
		t.Error("genuinely missing private artifact was not reported as absent")
	}
	newPath := filepath.Join(path+".d", receipt.Generation, "new.token")
	if os.Symlink(newPath+".missing", newPath) != nil {
		t.Fatal("could not create dangling artifact symlink")
	}
	if _, err := store.Load("new"); err == nil || errors.Is(err, vault.ErrNotFound) {
		t.Error("dangling symlink was treated as an absent credential")
	}
	if os.Remove(newPath) != nil || os.WriteFile(newPath, []byte(ioNewToken+"\n"), 0o600) != nil || os.Chmod(newPath, 0o644) != nil {
		t.Fatal("could not prepare unsafe artifact permissions")
	}
	if _, err := store.Load("new"); err == nil || errors.Is(err, vault.ErrNotFound) {
		t.Error("unsafe existing credential was treated as absent")
	}
}
