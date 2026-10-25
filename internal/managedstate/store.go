package managedstate

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Store serializes cooperating writers with an exclusive sidecar lock. It also
// refuses replacement of the inventory or lock by an external local writer.
// The filesystem and files owned by the invoking local user are trusted.
type Store struct {
	mu       sync.Mutex
	path     string
	state    State
	identity os.FileInfo
	digest   [sha256.Size]byte
	lock     *os.File
	lockInfo os.FileInfo
	closed   bool
}

func privateRegular(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0
}

func readSnapshot(path string) (State, []byte, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return State{}, nil, nil, ErrStateIO
	}
	if !privateRegular(before) {
		return State{}, nil, nil, ErrInvalidState
	}
	file, err := os.Open(path)
	if err != nil {
		return State{}, nil, nil, ErrStateIO
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !privateRegular(opened) || !os.SameFile(before, opened) {
		return State{}, nil, nil, ErrStateChanged
	}
	body, err := io.ReadAll(io.LimitReader(file, MaxInputBytes+1))
	if err != nil {
		return State{}, nil, nil, ErrStateIO
	}
	after, err := file.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !privateRegular(current) || !os.SameFile(opened, current) || !os.SameFile(opened, after) || opened.Size() != after.Size() || !opened.ModTime().Equal(after.ModTime()) {
		return State{}, nil, nil, ErrStateChanged
	}
	state, err := Decode(bytes.NewReader(body))
	if err != nil {
		return State{}, nil, nil, err
	}
	return state, body, current, nil
}

// Read never acquires a lock, creates an artifact, changes modes or repairs an
// inventory. Concurrent atomic saves return a complete snapshot or a conflict.
func Read(path string) (State, error) {
	state, _, _, err := readSnapshot(path)
	return state, err
}

func encode(state State) ([]byte, State, error) {
	if Validate(state) != nil {
		return nil, State{}, ErrInvalidState
	}
	state = clone(state)
	sort.Slice(state.Resources, func(i, j int) bool { return state.Resources[i].ID < state.Resources[j].ID })
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil || len(body)+1 > MaxInputBytes {
		return nil, State{}, ErrInvalidState
	}
	return append(body, '\n'), state, nil
}

func removeOwned(path string, identity os.FileInfo) {
	current, err := os.Lstat(path)
	if err == nil && identity != nil && current.Mode().IsRegular() && os.SameFile(identity, current) {
		_ = os.Remove(path)
	}
}

func syncDirectory(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return ErrStateIO
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return ErrStateIO
	}
	return nil
}

// A completed sibling temporary can be installed by rename for an existing
// inventory or an exclusive hard link for a new one. Its name contains no data.
func prepareFile(path string, body []byte) (string, os.FileInfo, error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".secretwright-state-*")
	if err != nil {
		return "", nil, ErrStateIO
	}
	name := file.Name()
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return "", nil, ErrStateIO
	}
	abort := func() (string, os.FileInfo, error) {
		_ = file.Close()
		removeOwned(name, info)
		return "", nil, ErrStateIO
	}
	if file.Chmod(0o600) != nil {
		return abort()
	}
	written, err := file.Write(body)
	if err != nil || written != len(body) || file.Sync() != nil {
		return abort()
	}
	if file.Close() != nil {
		removeOwned(name, info)
		return "", nil, ErrStateIO
	}
	return name, info, nil
}

// Create publishes a fully written private inventory without overwriting an
// existing file or following a final symlink. The destination becomes visible
// only after the complete contents have been written and synced.
func Create(path string, state State) error {
	body, _, err := encode(state)
	if err != nil {
		return err
	}
	temporary, identity, err := prepareFile(path, body)
	if err != nil {
		return err
	}
	defer removeOwned(temporary, identity)
	if err := os.Link(temporary, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrStateChanged
		}
		return ErrStateIO
	}
	if syncDirectory(path) != nil {
		return ErrStateUnconfirmed
	}
	return nil
}

// Lock never steals a stale lock. The operator must first establish that no
// writer is active before manually removing a lock left by a crashed process.
func Lock(path string) (*Store, error) {
	file, err := os.OpenFile(path+".lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrStateLocked
		}
		return nil, ErrStateIO
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, ErrStateIO
	}
	if file.Chmod(0o600) != nil {
		_ = file.Close()
		removeOwned(path+".lock", info)
		return nil, ErrStateIO
	}
	state, body, identity, err := readSnapshot(path)
	if err != nil {
		_ = file.Close()
		removeOwned(path+".lock", info)
		return nil, err
	}
	return &Store{path: path, state: state, identity: identity, digest: sha256.Sum256(body), lock: file, lockInfo: info}, nil
}

func (store *Store) ownsLock() bool {
	if store.closed || store.lock == nil {
		return false
	}
	info, err := os.Lstat(store.path + ".lock")
	return err == nil && privateRegular(info) && os.SameFile(store.lockInfo, info)
}

// Snapshot returns independent metadata; callers cannot change a checkpoint by
// mutating a slice they received from a previous call.
func (store *Store) Snapshot() State {
	if store == nil {
		return State{}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return clone(store.state)
}

func (store *Store) unchanged() bool {
	if !store.ownsLock() {
		return false
	}
	_, body, identity, err := readSnapshot(store.path)
	return err == nil && os.SameFile(store.identity, identity) && sha256.Sum256(body) == store.digest
}

// Save requires exactly one revision of progress and a stable target binding.
// A successful return includes syncing the containing directory after rename.
// The caller must stop on every error, including an unconfirmed durability step.
func (store *Store) Save(next State) error {
	if store == nil {
		return ErrStateChanged
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	body, normalized, err := encode(next)
	if err != nil {
		return err
	}
	if next.Revision != store.state.Revision+1 || next.Blueprint != store.state.Blueprint || next.Target != store.state.Target || !store.unchanged() {
		return ErrStateChanged
	}
	temporary, identity, err := prepareFile(store.path, body)
	if err != nil {
		return err
	}
	defer removeOwned(temporary, identity)
	if !store.unchanged() {
		return ErrStateChanged
	}
	if os.Rename(temporary, store.path) != nil {
		return ErrStateIO
	}
	store.state, store.identity, store.digest = normalized, identity, sha256.Sum256(body)
	current, err := os.Lstat(store.path)
	if err != nil || !privateRegular(current) || !os.SameFile(identity, current) || syncDirectory(store.path) != nil {
		return ErrStateUnconfirmed
	}
	return nil
}

// Close releases only the inode reserved by this Store. A replacement sidecar
// belongs to somebody else and must not be unlinked, even when it has our name.
func (store *Store) Close() error {
	if store == nil {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.closed {
		return nil
	}
	if store.lock == nil {
		store.closed = true
		return ErrStateChanged
	}
	owned := store.ownsLock()
	store.closed = true
	err := store.lock.Close()
	store.lock = nil
	if !owned {
		return ErrStateChanged
	}
	current, pathErr := os.Lstat(store.path + ".lock")
	if pathErr != nil || !privateRegular(current) || !os.SameFile(store.lockInfo, current) {
		return ErrStateChanged
	}
	if os.Remove(store.path+".lock") != nil || err != nil {
		return ErrStateIO
	}
	return nil
}
