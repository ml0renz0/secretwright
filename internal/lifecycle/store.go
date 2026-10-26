package lifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/ml0renz0/secretwright/internal/fileformat"
)

// Store binds one local rotation checkpoint to an existing private consumer.
// Cooperating writers use an exclusive sidecar; inode and byte proofs detect
// replacement by other local writers. Secret artifacts remain after Close.
type Store struct {
	mu                  sync.Mutex
	spec                Spec
	path                string
	state               Receipt
	identity            os.FileInfo
	digest              string
	consumerIdentity    os.FileInfo
	consumerDigest      string
	consumerParent      os.FileInfo
	receiptParent       os.FileInfo
	artifactRoot        os.FileInfo
	generationDirectory os.FileInfo
	lock                *os.File
	lockInfo            os.FileInfo
	writable            bool
	closed              bool
}

var _ Session = (*Store)(nil)

func cleanStorePath(path string) (string, error) {
	if path == "" || path == "-" || !utf8.ValidString(path) || strings.IndexFunc(path, func(r rune) bool { return unicode.IsControl(r) }) >= 0 {
		return "", ErrInvalidLifecycle
	}
	absolute, err := filepath.Abs(path)
	if err != nil || absolute == filepath.VolumeName(absolute)+string(filepath.Separator) {
		return "", ErrInvalidLifecycle
	}
	return filepath.Clean(absolute), nil
}

func readRotationReceipt(path string) (Receipt, []byte, os.FileInfo, error) {
	body, identity, err := readPrivateBytes(path, privateDocumentLimit)
	if err != nil {
		return Receipt{}, nil, nil, err
	}
	receipt, err := DecodeReceipt(bytes.NewReader(body))
	if err != nil {
		return Receipt{}, nil, nil, err
	}
	if json.Valid(body) != (receipt.Format == fileformat.JSON) {
		return Receipt{}, nil, nil, ErrInvalidLifecycle
	}
	return receipt, body, identity, nil
}

// Open performs all local validation without reading operator credentials or
// contacting Vault. Read-only stores create no files, directories, or locks.
func Open(spec Spec, path string, format fileformat.Format, writable bool) (*Store, error) {
	normalized, err := ValidateSpec(spec)
	if err != nil {
		return nil, ErrInvalidLifecycle
	}
	if format != "" && format != fileformat.YAML && format != fileformat.JSON {
		return nil, ErrInvalidLifecycle
	}
	path, err = cleanStorePath(path)
	if err != nil {
		return nil, err
	}
	if path == normalized.Consumer.Path || path+".lock" == normalized.Consumer.Path || strings.HasPrefix(normalized.Consumer.Path, path+".d"+string(filepath.Separator)) {
		return nil, ErrConflict
	}
	consumer, consumerIdentity, err := readPrivateToken(normalized.Consumer.Path)
	if err != nil {
		return nil, err
	}
	consumerParent, err := os.Stat(filepath.Dir(normalized.Consumer.Path))
	if err != nil || !consumerParent.IsDir() {
		return nil, ErrIO
	}
	receiptParent, err := os.Stat(filepath.Dir(path))
	if err != nil || !receiptParent.IsDir() {
		return nil, ErrIO
	}
	store := &Store{spec: normalized, path: path, consumerIdentity: consumerIdentity, consumerDigest: consumer.Digest, consumerParent: consumerParent, receiptParent: receiptParent, writable: writable}
	if writable {
		file, err := os.OpenFile(path+".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				return nil, ErrConflict
			}
			return nil, ErrIO
		}
		store.lock = file
		store.lockInfo, err = file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, ErrUnconfirmed
		}
		if file.Chmod(0o600) != nil {
			_ = store.Close()
			return nil, ErrIO
		}
	}
	fail := func(err error) (*Store, error) { _ = store.Close(); return nil, err }
	_, err = os.Lstat(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fail(ErrIO)
		}
		if format == "" {
			format = fileformat.YAML
		}
		store.state = Receipt{Format: format}
	} else {
		receipt, body, identity, err := readRotationReceipt(path)
		if err != nil {
			return fail(err)
		}
		if receipt.Name != normalized.Name || receipt.ConfigSHA256 != SpecHash(normalized) || (format != "" && format != receipt.Format) {
			return fail(ErrConflict)
		}
		store.state, store.identity, store.digest = receipt, identity, privateDigest(body)
		if err := store.bindArtifacts(); err != nil {
			return fail(err)
		}
	}
	if !store.parentsUnchanged() {
		return fail(ErrConflict)
	}
	return store, nil
}

func (store *Store) parentsUnchanged() bool {
	consumer, consumerErr := os.Stat(filepath.Dir(store.spec.Consumer.Path))
	receipt, receiptErr := os.Stat(filepath.Dir(store.path))
	return consumerErr == nil && receiptErr == nil && consumer.IsDir() && receipt.IsDir() && os.SameFile(store.consumerParent, consumer) && os.SameFile(store.receiptParent, receipt)
}

func (store *Store) ownsLock() bool {
	if store.closed || !store.writable || store.lock == nil {
		return false
	}
	info, err := os.Lstat(store.path + ".lock")
	return err == nil && privateRegular(info) && os.SameFile(store.lockInfo, info)
}

func (store *Store) receiptUnchanged() bool {
	if store.closed || !store.parentsUnchanged() {
		return false
	}
	if store.identity == nil {
		_, err := os.Lstat(store.path)
		return errors.Is(err, os.ErrNotExist)
	}
	_, body, identity, err := readRotationReceipt(store.path)
	return err == nil && os.SameFile(store.identity, identity) && privateDigest(body) == store.digest
}

func (store *Store) mayWrite() bool { return store.ownsLock() && store.receiptUnchanged() }

func (store *Store) Snapshot() Receipt {
	if store == nil {
		return Receipt{}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.state
}

func (store *Store) consumer() (PrivateFile, os.FileInfo, error) {
	if store.closed || !store.parentsUnchanged() {
		return PrivateFile{}, nil, ErrConflict
	}
	value, identity, err := readPrivateToken(store.spec.Consumer.Path)
	if err != nil || !os.SameFile(store.consumerIdentity, identity) || value.Digest != store.consumerDigest {
		return PrivateFile{}, nil, ErrConflict
	}
	return value, identity, nil
}

func (store *Store) Consumer() (PrivateFile, error) {
	if store == nil {
		return PrivateFile{}, ErrConflict
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, _, err := store.consumer()
	return value, err
}

func (store *Store) generationPath() string {
	return filepath.Join(store.path+".d", store.state.Generation)
}

func (store *Store) directoriesUnchanged() bool {
	root, rootErr := os.Lstat(store.path + ".d")
	generation, generationErr := os.Lstat(store.generationPath())
	return rootErr == nil && generationErr == nil && privateDirectory(root) && privateDirectory(generation) && store.artifactRoot != nil && store.generationDirectory != nil && os.SameFile(store.artifactRoot, root) && os.SameFile(store.generationDirectory, generation)
}

func (store *Store) bindArtifacts() error {
	root, err := os.Lstat(store.path + ".d")
	if err != nil || !privateDirectory(root) {
		return ErrConflict
	}
	generation, err := os.Lstat(store.generationPath())
	if err != nil || !privateDirectory(generation) {
		return ErrConflict
	}
	store.artifactRoot, store.generationDirectory = root, generation
	for _, proof := range []struct{ kind, digest string }{{"old", store.state.OldDigest}, {"bundle", store.state.BundleDigest}, {"new", store.state.NewDigest}} {
		if proof.digest == "" {
			continue
		}
		value, _, err := store.load(proof.kind)
		if err != nil || value.Digest != proof.digest {
			return ErrConflict
		}
	}
	return nil
}

func (store *Store) createGeneration(generation string) error {
	rootPath := store.path + ".d"
	root, err := os.Lstat(rootPath)
	if errors.Is(err, os.ErrNotExist) {
		if os.Mkdir(rootPath, 0o700) != nil {
			return ErrIO
		}
		root, err = os.Lstat(rootPath)
		if err != nil || !privateDirectory(root) {
			return ErrUnconfirmed
		}
		if syncPrivateDirectory(filepath.Dir(rootPath)) != nil {
			return ErrUnconfirmed
		}
	}
	if err != nil || !privateDirectory(root) || (store.artifactRoot != nil && !os.SameFile(store.artifactRoot, root)) {
		return ErrConflict
	}
	store.artifactRoot = root
	path := filepath.Join(rootPath, generation)
	if err := os.Mkdir(path, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrConflict
		}
		return ErrIO
	}
	info, err := os.Lstat(path)
	if err != nil || !privateDirectory(info) || syncPrivateDirectory(rootPath) != nil {
		return ErrUnconfirmed
	}
	currentRoot, err := os.Lstat(rootPath)
	if err != nil || !privateDirectory(currentRoot) || !os.SameFile(root, currentRoot) {
		return ErrUnconfirmed
	}
	store.generationDirectory = info
	return nil
}

func (store *Store) boundReceipt(next Receipt) bool {
	return next.Name == store.spec.Name && next.ConfigSHA256 == SpecHash(store.spec) && next.Format == store.state.Format
}

func (store *Store) writeReceipt(next Receipt) error {
	if ValidateReceipt(next) != nil {
		return ErrInvalidLifecycle
	}
	body, err := json.Marshal(next)
	if err != nil {
		return ErrInvalidLifecycle
	}
	body, err = fileformat.EncodeJSON(body, next.Format)
	if err != nil || len(body) > privateDocumentLimit {
		return ErrInvalidLifecycle
	}
	if !store.mayWrite() {
		return ErrConflict
	}
	temporary, identity, err := preparePrivateFile(store.path, body, nil)
	if err != nil {
		return err
	}
	defer removePrivateOwned(temporary, identity)
	if !store.mayWrite() {
		return ErrConflict
	}
	if store.identity == nil {
		if err := os.Link(temporary, store.path); err != nil {
			if errors.Is(err, os.ErrExist) {
				return ErrConflict
			}
			return ErrIO
		}
	} else if os.Rename(temporary, store.path) != nil {
		return ErrIO
	}
	store.state, store.identity, store.digest = next, identity, privateDigest(body)
	current, err := os.Lstat(store.path)
	if err != nil || !privateRegular(current) || !os.SameFile(identity, current) || syncPrivateDirectory(filepath.Dir(store.path)) != nil {
		return ErrUnconfirmed
	}
	return nil
}

// Prepare backs up the original raw credential before publishing the initial
// write-ahead checkpoint. A terminal generation can start a distinct one.
func (store *Store) Prepare(next Receipt, old PrivateFile) error {
	if store == nil {
		return ErrConflict
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.mayWrite() {
		return ErrConflict
	}
	if ValidateReceipt(next) != nil {
		return ErrInvalidLifecycle
	}
	if !store.boundReceipt(next) || next.Phase != "prepared" || next.NewDigest != "" || next.BundleDigest != "" {
		return ErrConflict
	}
	if store.state.APIVersion == "" {
		if next.Revision != 1 {
			return ErrConflict
		}
	} else if (store.state.Phase != "retired" && store.state.Phase != "aborted") || next.Revision != store.state.Revision+1 || next.Generation == store.state.Generation || next.Target != store.state.Target || next.RoleIdentity != store.state.RoleIdentity || next.EntityID != store.state.EntityID {
		return ErrConflict
	}
	consumer, _, err := store.consumer()
	if err != nil {
		return err
	}
	provided, err := privateValue(old.Data, true)
	if err != nil || old.Token != provided.Token || old.Digest != provided.Digest || consumer.Digest != old.Digest || !bytes.Equal(consumer.Data, old.Data) || next.OldDigest != consumer.Digest {
		return ErrConflict
	}
	if err := store.createGeneration(next.Generation); err != nil {
		return err
	}
	if err := createPrivateArtifact(filepath.Join(store.path+".d", next.Generation, "old.token"), consumer.Data); err != nil {
		return err
	}
	if !store.mayWrite() {
		return ErrConflict
	}
	return store.writeReceipt(next)
}

func (store *Store) Save(next Receipt) error {
	if store == nil {
		return ErrConflict
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.mayWrite() || store.state.APIVersion == "" {
		return ErrConflict
	}
	if ValidateReceipt(next) != nil {
		return ErrInvalidLifecycle
	}
	previous := store.state
	if !store.boundReceipt(next) || next.Revision != previous.Revision+1 || next.Generation != previous.Generation || next.Target != previous.Target || next.RoleIdentity != previous.RoleIdentity || next.EntityID != previous.EntityID || next.OldDigest != previous.OldDigest || (previous.NewDigest != "" && next.NewDigest != previous.NewDigest) || (previous.BundleDigest != "" && next.BundleDigest != previous.BundleDigest) || !store.directoriesUnchanged() {
		return ErrConflict
	}
	return store.writeReceipt(next)
}

func (store *Store) load(kind string) (PrivateFile, os.FileInfo, error) {
	name, ok := artifactName(kind)
	if !ok {
		return PrivateFile{}, nil, ErrInvalidLifecycle
	}
	if store.closed || store.state.APIVersion == "" || !store.directoriesUnchanged() {
		return PrivateFile{}, nil, ErrConflict
	}
	limit := int64(privateTokenLimit)
	if kind == "bundle" {
		limit = privateDocumentLimit
	}
	body, identity, err := readPrivateBytes(filepath.Join(store.generationPath(), name), limit)
	if err != nil {
		return PrivateFile{}, nil, err
	}
	value, err := artifactValue(kind, body)
	if err != nil {
		return PrivateFile{}, nil, err
	}
	if !store.directoriesUnchanged() {
		return PrivateFile{}, nil, ErrConflict
	}
	return value, identity, nil
}

func (store *Store) Load(kind string) (PrivateFile, error) {
	if store == nil {
		return PrivateFile{}, ErrConflict
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.receiptUnchanged() {
		return PrivateFile{}, ErrConflict
	}
	value, _, err := store.load(kind)
	return value, err
}

func (store *Store) Put(kind string, body []byte) error {
	if store == nil {
		return ErrConflict
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.mayWrite() || store.state.APIVersion == "" {
		return ErrConflict
	}
	name, ok := artifactName(kind)
	if !ok {
		return ErrInvalidLifecycle
	}
	value, err := artifactValue(kind, body)
	if err != nil {
		return err
	}
	if !store.directoriesUnchanged() {
		return ErrConflict
	}
	if err := createPrivateArtifact(filepath.Join(store.generationPath(), name), value.Data); err != nil {
		return err
	}
	if !store.mayWrite() || !store.directoriesUnchanged() {
		return ErrUnconfirmed
	}
	return nil
}

// Publish replaces the consumer only after the engine's pending checkpoint.
// It preserves its owner and mode, confirms the new bytes, and never restores
// the old credential after a potentially visible publication.
func (store *Store) Publish(expectedOldDigest string) error {
	if store == nil {
		return ErrConflict
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.mayWrite() || store.state.Phase != "pending_publish" || expectedOldDigest == "" || expectedOldDigest != store.state.OldDigest || store.state.NewDigest == expectedOldDigest {
		return ErrConflict
	}
	candidate, candidateIdentity, err := store.load("new")
	if err != nil || candidate.Digest != store.state.NewDigest {
		return ErrConflict
	}
	old, original, err := store.consumer()
	if err != nil || old.Digest != expectedOldDigest {
		return ErrConflict
	}
	temporary, identity, err := preparePrivateFile(store.spec.Consumer.Path, candidate.Data, original)
	if err != nil {
		return err
	}
	defer removePrivateOwned(temporary, identity)
	if !store.mayWrite() {
		return ErrConflict
	}
	old, _, err = store.consumer()
	if err != nil || old.Digest != expectedOldDigest {
		return ErrConflict
	}
	currentCandidate, currentIdentity, err := store.load("new")
	if err != nil || !os.SameFile(candidateIdentity, currentIdentity) || currentCandidate.Digest != candidate.Digest {
		return ErrConflict
	}
	if os.Rename(temporary, store.spec.Consumer.Path) != nil {
		return ErrIO
	}
	store.consumerIdentity, store.consumerDigest = identity, candidate.Digest
	if syncPrivateDirectory(filepath.Dir(store.spec.Consumer.Path)) != nil {
		return ErrUnconfirmed
	}
	confirmed, _, err := store.consumer()
	if err != nil || confirmed.Digest != candidate.Digest {
		return ErrUnconfirmed
	}
	return nil
}

// Close releases only the lock inode this Store created. A replacement lock is
// left untouched, and all private generation artifacts remain for recovery.
func (store *Store) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	if !store.writable {
		store.closed = true
		return nil
	}
	owned := store.ownsLock()
	store.closed = true
	var closeErr error
	if store.lock != nil {
		closeErr = store.lock.Close()
		store.lock = nil
	}
	if !owned {
		return ErrConflict
	}
	current, err := os.Lstat(store.path + ".lock")
	if err != nil || !privateRegular(current) || !os.SameFile(store.lockInfo, current) {
		return ErrConflict
	}
	if os.Remove(store.path+".lock") != nil || closeErr != nil {
		return ErrIO
	}
	return nil
}
