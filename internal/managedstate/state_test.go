package managedstate_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/ml0renz0/secretwright/internal/managedstate"
)

func testState() managedstate.State {
	hash := strings.Repeat("a", 64)
	return managedstate.State{
		APIVersion: "secretwright/state/v1", Blueprint: "app-dev", Revision: 1,
		Target: managedstate.Target{AddressSHA256: hash, ClusterID: "11111111-1111-4111-8111-111111111111", Namespace: "team"},
		Resources: []managedstate.Record{
			{ID: "entity_owner", Kind: "entity", Name: "app-owner", RemoteID: "22222222-2222-4222-8222-222222222222", IdentitySHA256: hash, Fingerprint: hash},
			{ID: "group_team", Kind: "group", Name: "app-team", RemoteID: "33333333-3333-4333-8333-333333333333", IdentitySHA256: hash, Fingerprint: hash},
			{ID: "mount_data", Kind: "kv_mount", Name: "team/kv", RemoteID: "kv_private-accessor", IdentitySHA256: hash, Fingerprint: hash},
			{ID: "policy_read", Kind: "policy", Name: "app-read", Fingerprint: hash},
			{ID: "role_app", Kind: "approle", Name: "app-role", AuthMount: "custom/approle", IdentitySHA256: hash, Fingerprint: hash},
		},
	}
}

func stateJSON(t *testing.T, state managedstate.State) []byte {
	t.Helper()
	body, err := json.Marshal(state)
	if err != nil {
		t.Fatal("could not encode state test fixture")
	}
	return body
}

func requirePrivateStateError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("unsafe inventory operation was accepted")
	}
	for _, marker := range []string{"private-", "secretwright-state-test", "private-marker.invalid", "secret_id", "policy-body"} {
		if strings.Contains(err.Error(), marker) {
			t.Error("inventory diagnostic exposed a file path or rejected content")
		}
	}
}

func privateStateFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private-state.json")
	if err := managedstate.Create(path, testState()); err != nil {
		t.Fatal("could not create private state test fixture")
	}
	return path
}

func readFixtureBytes(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("could not inspect state fixture bytes")
	}
	return body
}

func assertUnchanged(t *testing.T, path string, before []byte) {
	t.Helper()
	if !bytes.Equal(readFixtureBytes(t, path), before) {
		t.Error("rejected inventory operation changed the existing file")
	}
}

func TestStateDecodeAcceptsOnlyBoundedStrictVersionedMetadata(t *testing.T) {
	valid := stateJSON(t, testState())
	actual, err := managedstate.Decode(bytes.NewReader(valid))
	if err != nil || !reflect.DeepEqual(actual, testState()) || managedstate.Validate(actual) != nil {
		t.Fatal("valid private inventory did not round trip")
	}
	for _, source := range [][]byte{
		[]byte(strings.Replace(string(valid), `"revision":1`, `"revision":1,"revision":2`, 1)),
		[]byte(strings.Replace(string(valid), `"namespace":"team"`, `"namespace":"team","namespace":"private-repeated"`, 1)),
		[]byte(strings.Replace(string(valid), `"kind":"policy"`, `"kind":"policy","kind":"entity"`, 1)),
		[]byte(strings.Replace(string(valid), `"revision":1`, `"revision":1,"private-unknown":"private-value"`, 1)),
		[]byte(strings.Replace(string(valid), `"namespace":"team"`, `"namespace":"team","token":"private-token"`, 1)),
		[]byte(strings.Replace(string(valid), `"namespace":"team"`, `"namespace":null`, 1)),
		[]byte(strings.Replace(string(valid), `"namespace":"team"`, `"Namespace":"team"`, 1)),
		[]byte(strings.Replace(string(valid), `"kind":"policy"`, `"kind":"policy","spec":{"policy":"private-policy-body"}`, 1)),
		[]byte(strings.Replace(string(valid), `"kind":"policy"`, `"kind":"policy","pending":null`, 1)),
		[]byte(strings.Replace(string(valid), `"revision":1`, `"revision":"1"`, 1)),
		[]byte(strings.Replace(string(valid), `"revision":1`, `"revision":1.0`, 1)),
		[]byte(strings.Replace(string(valid), `"revision":1`, `"revision":1e0`, 1)),
		[]byte(strings.Replace(string(valid), `"revision":1`, `"revision":9223372036854775808`, 1)),
		[]byte(strings.Replace(string(valid), `"namespace":"team"`, `"namespace":"private-\u0000marker"`, 1)),
		append(append([]byte(nil), valid...), []byte("\n{}")...),
		append(append([]byte(nil), valid...), bytes.Repeat([]byte(" "), (1<<20)+1)...),
		[]byte("api_version: secretwright/state/v1\nprivate-marker: true\n"),
		[]byte("[]"), []byte("null"), []byte("{}"), []byte(""), []byte{0xff},
	} {
		state, err := managedstate.Decode(bytes.NewReader(source))
		if err != managedstate.ErrInvalidState || !reflect.DeepEqual(state, managedstate.State{}) {
			t.Error("invalid inventory returned partial metadata or a non-static error")
		}
		requirePrivateStateError(t, err)
	}
	if state, err := managedstate.Decode(nil); err != managedstate.ErrInvalidState || !reflect.DeepEqual(state, managedstate.State{}) {
		t.Error("missing reader returned partial state or an unsafe error")
	}
	if state, err := managedstate.Decode(stateFailedReader{}); err != managedstate.ErrInvalidState || !reflect.DeepEqual(state, managedstate.State{}) {
		t.Error("failed reader returned partial state or propagated its diagnostic")
	}
}

type stateFailedReader struct{}

func (stateFailedReader) Read([]byte) (int, error) { return 0, errors.New("private-reader-marker") }

func TestStateValidationRejectsAmbiguousOwnershipAndInvalidPendingRecords(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*managedstate.State)
	}{
		{"future version", func(s *managedstate.State) { s.APIVersion = "secretwright/state/v999" }},
		{"empty blueprint", func(s *managedstate.State) { s.Blueprint = "" }},
		{"zero revision", func(s *managedstate.State) { s.Revision = 0 }},
		{"overflow revision", func(s *managedstate.State) { s.Revision = 1 << 63 }},
		{"nil list", func(s *managedstate.State) { s.Resources = nil }},
		{"bad address digest", func(s *managedstate.State) { s.Target.AddressSHA256 = "https://private-marker.invalid" }},
		{"upper digest", func(s *managedstate.State) { s.Target.AddressSHA256 = strings.Repeat("A", 64) }},
		{"missing cluster", func(s *managedstate.State) { s.Target.ClusterID = "" }},
		{"unsafe namespace", func(s *managedstate.State) { s.Target.Namespace = "private-team\n" }},
		{"duplicate logical ID", func(s *managedstate.State) { s.Resources[1].ID = s.Resources[0].ID }},
		{"duplicate locator", func(s *managedstate.State) { s.Resources = append(s.Resources, managedstate.Record{ID: "other", Kind: "policy", Name: "app-read", Fingerprint: strings.Repeat("a", 64)}) }},
		{"unknown kind", func(s *managedstate.State) { s.Resources[0].Kind = "private-kind" }},
		{"unsafe logical ID", func(s *managedstate.State) { s.Resources[0].ID = "private/id" }},
		{"unsafe name", func(s *managedstate.State) { s.Resources[0].Name = "private*name" }},
		{"missing identity", func(s *managedstate.State) { s.Resources[0].IdentitySHA256 = "" }},
		{"invalid identity UUID", func(s *managedstate.State) { s.Resources[0].RemoteID = "private-identity" }},
		{"raw role credential", func(s *managedstate.State) { s.Resources[4].RemoteID = "private-role-id" }},
		{"missing role auth mount", func(s *managedstate.State) { s.Resources[4].AuthMount = "" }},
		{"auth on another kind", func(s *managedstate.State) { s.Resources[3].AuthMount = "approle" }},
		{"missing baseline", func(s *managedstate.State) { s.Resources[3].Fingerprint = "" }},
		{"unknown pending", func(s *managedstate.State) { s.Resources[3].Pending = "private-operation" }},
		{"pending update without baseline", func(s *managedstate.State) { s.Resources[3].Pending = "update"; s.Resources[3].Fingerprint = "" }},
		{"pending create with claimed identity", func(s *managedstate.State) { s.Resources[0].Pending = "create"; s.Resources[0].Fingerprint = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := testState()
			test.edit(&state)
			err := managedstate.Validate(state)
			if err != managedstate.ErrInvalidState {
				t.Error("invalid ownership metadata did not return its fixed validation error")
			}
		})
	}
	empty := testState()
	empty.Resources = []managedstate.Record{}
	if managedstate.Validate(empty) != nil {
		t.Error("empty explicit inventory cannot initialize a clean target")
	}
	pending := testState()
	pending.Resources[0] = managedstate.Record{ID: "new_entity", Kind: "entity", Name: "app-new", Pending: "create"}
	pending.Resources[3].Pending = "update"
	if managedstate.Validate(pending) != nil {
		t.Error("valid write-ahead checkpoints cannot be persisted")
	}
	large := testState()
	large.Resources = make([]managedstate.Record, managedstate.MaxResources+1)
	for index := range large.Resources {
		large.Resources[index] = managedstate.Record{ID: fmt.Sprintf("p%d", index), Kind: "policy", Name: fmt.Sprintf("p%d", index), Fingerprint: strings.Repeat("a", 64)}
	}
	if managedstate.Validate(large) != managedstate.ErrInvalidState {
		t.Error("inventory resource limit was silently exceeded")
	}
}

func TestStateCreationIsExclusivePrivateAndCanonical(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private-inventory.json")
	state := testState()
	for left, right := 0, len(state.Resources)-1; left < right; left, right = left+1, right-1 {
		state.Resources[left], state.Resources[right] = state.Resources[right], state.Resources[left]
	}
	if err := managedstate.Create(path, state); err != nil {
		t.Fatal("valid inventory could not be created")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("created inventory was not a private regular file")
	}
	loaded, err := managedstate.Read(path)
	if err != nil || !reflect.DeepEqual(loaded, testState()) {
		t.Error("inventory was not serialized in canonical resource order")
	}
	before := readFixtureBytes(t, path)
	requirePrivateStateError(t, managedstate.Create(path, testState()))
	assertUnchanged(t, path, before)
	link := filepath.Join(filepath.Dir(path), "private-link.json")
	if os.Symlink(path, link) != nil {
		t.Fatal("could not create a symlink fixture")
	}
	requirePrivateStateError(t, managedstate.Create(link, testState()))
	if _, err := managedstate.Read(link); err == nil {
		t.Error("inventory read followed a final symlink")
	}
	assertUnchanged(t, path, before)
	if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
		t.Error("read-only inventory access created a lock artifact")
	}
}

func TestStateReadRejectsNonPrivateFilesWithoutRepairingTheirPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o700, 0o000} {
		t.Run(fmt.Sprintf("mode-%o", mode), func(t *testing.T) {
			path := privateStateFile(t)
			if os.Chmod(path, mode) != nil {
				t.Fatal("could not change fixture permissions")
			}
			_, err := managedstate.Read(path)
			requirePrivateStateError(t, err)
			info, err := os.Lstat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Error("inventory read repaired an untrusted file's permissions")
			}
		})
	}
	if _, err := managedstate.Read(t.TempDir()); err == nil {
		t.Error("inventory read accepted a non-regular file")
	}
}

func TestStateLockIsExclusiveDoesNotStealAndSnapshotsAreDetached(t *testing.T) {
	path := privateStateFile(t)
	store, err := managedstate.Lock(path)
	if err != nil {
		t.Fatal("could not acquire inventory lock")
	}
	defer store.Close()
	if other, err := managedstate.Lock(path); other != nil || !errors.Is(err, managedstate.ErrStateLocked) {
		t.Error("second writer obtained an already held inventory")
	}
	snapshot := store.Snapshot()
	snapshot.Resources[0].Name = "private-mutated-name"
	snapshot.Target.Namespace = "private-mutated-namespace"
	if !reflect.DeepEqual(store.Snapshot(), testState()) {
		t.Error("caller mutation changed the held inventory baseline")
	}
	if err := store.Close(); err != nil {
		t.Error("could not release owned inventory lock")
	}
	if _, err := os.Lstat(path + ".lock"); !os.IsNotExist(err) {
		t.Error("closing the store retained its owned lock")
	}
	if err := os.WriteFile(path+".lock", []byte("private-stale-lock"), 0o600); err != nil {
		t.Fatal("could not provision a stale lock fixture")
	}
	if other, err := managedstate.Lock(path); other != nil || !errors.Is(err, managedstate.ErrStateLocked) {
		t.Error("writer automatically stole an unknown or stale lock")
	}
	if string(readFixtureBytes(t, path+".lock")) != "private-stale-lock" {
		t.Error("rejected writer altered the stale lock")
	}
}

func TestStateSaveCheckpointsAtomicallyAndRejectsRevisionOrTargetChanges(t *testing.T) {
	path := privateStateFile(t)
	store, err := managedstate.Lock(path)
	if err != nil {
		t.Fatal("could not lock inventory")
	}
	defer store.Close()
	for _, edit := range []func(*managedstate.State){
		func(s *managedstate.State) {},
		func(s *managedstate.State) { s.Revision += 2 },
		func(s *managedstate.State) { s.Revision++; s.Blueprint = "other" },
		func(s *managedstate.State) { s.Revision++; s.Target.Namespace = "other" },
		func(s *managedstate.State) { s.Revision++; s.Resources[0].Fingerprint = "private-invalid-hash" },
	} {
		before := readFixtureBytes(t, path)
		next := store.Snapshot()
		edit(&next)
		requirePrivateStateError(t, store.Save(next))
		assertUnchanged(t, path, before)
	}
	next := store.Snapshot()
	next.Revision++
	next.Resources[0].Pending = "update"
	if err := store.Save(next); err != nil {
		t.Fatal("could not persist the pending mutation before a write")
	}
	loaded, err := managedstate.Read(path)
	if err != nil || !reflect.DeepEqual(loaded, next) || !reflect.DeepEqual(store.Snapshot(), next) {
		t.Fatal("pending checkpoint was not durably visible as a full snapshot")
	}
	next.Revision++
	next.Resources[0].Pending = ""
	next.Resources[0].Fingerprint = strings.Repeat("b", 64)
	if err := store.Save(next); err != nil {
		t.Fatal("could not confirm an applied mutation checkpoint")
	}
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Error("checkpoint replacement weakened inventory permissions")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 2 {
		t.Error("inventory checkpoint retained an unexpected temporary artifact")
	}
}

func TestStateSaveNeverOverwritesAnExternalEditOrReplacement(t *testing.T) {
	for _, change := range []string{"content", "inode", "permissions", "symlink"} {
		t.Run(change, func(t *testing.T) {
			path := privateStateFile(t)
			store, err := managedstate.Lock(path)
			if err != nil {
				t.Fatal("could not lock inventory")
			}
			defer store.Close()
			external := store.Snapshot()
			external.Revision++
			external.Resources[0].Fingerprint = strings.Repeat("c", 64)
			body := stateJSON(t, external)
			if change == "inode" {
				// Equal bytes must not let a new inode inherit the old writer's
				// authority. This is distinct from detecting an edited payload.
				body = readFixtureBytes(t, path)
			}
			switch change {
			case "content":
				if os.WriteFile(path, body, 0o600) != nil {
					t.Fatal("could not change fixture content")
				}
			case "inode", "symlink":
				replacement := filepath.Join(filepath.Dir(path), "private-replacement")
				if os.WriteFile(replacement, body, 0o600) != nil || os.Remove(path) != nil {
					t.Fatal("could not prepare external replacement")
				}
				if change == "inode" {
					if os.Rename(replacement, path) != nil {
						t.Fatal("could not replace fixture inode")
					}
				} else if os.Symlink(replacement, path) != nil {
					t.Fatal("could not replace fixture with symlink")
				}
			case "permissions":
				if os.Chmod(path, 0o644) != nil {
					t.Fatal("could not change fixture permissions")
				}
			}
			before := readFixtureBytes(t, path)
			next := store.Snapshot()
			next.Revision++
			if err := store.Save(next); !errors.Is(err, managedstate.ErrStateChanged) {
				t.Error("state save did not reject a replaced ownership baseline")
			}
			assertUnchanged(t, path, before)
		})
	}
}

func TestStateCloseNeverRemovesAReplacedLockAndFailedOpenCleansOnlyItsOwnLock(t *testing.T) {
	path := privateStateFile(t)
	store, err := managedstate.Lock(path)
	if err != nil {
		t.Fatal("could not lock inventory")
	}
	parked := path + ".parked-lock"
	if os.Rename(path+".lock", parked) != nil || os.WriteFile(path+".lock", []byte("private-replacement-lock"), 0o600) != nil {
		t.Fatal("could not replace the held lock")
	}
	before := readFixtureBytes(t, path)
	next := store.Snapshot()
	next.Revision++
	if err := store.Save(next); !errors.Is(err, managedstate.ErrStateChanged) {
		t.Error("writer continued after losing ownership of its lock path")
	}
	assertUnchanged(t, path, before)
	_ = store.Close()
	if string(readFixtureBytes(t, path+".lock")) != "private-replacement-lock" {
		t.Error("store close removed or rewrote another writer's replacement lock")
	}
	broken := filepath.Join(t.TempDir(), "private-invalid.json")
	if os.WriteFile(broken, []byte(`{"private-unknown":true}`), 0o600) != nil {
		t.Fatal("could not create invalid state fixture")
	}
	if held, err := managedstate.Lock(broken); held != nil || err == nil {
		t.Error("writer acquired an invalid inventory")
	}
	if _, err := os.Lstat(broken+".lock"); !os.IsNotExist(err) {
		t.Error("failed state load left an owned lock behind")
	}
}

func TestStateConcurrentReadersSeeOnlyCompleteCheckpoints(t *testing.T) {
	path := privateStateFile(t)
	store, err := managedstate.Lock(path)
	if err != nil {
		t.Fatal("could not lock inventory")
	}
	defer store.Close()
	stop := make(chan struct{})
	var readers sync.WaitGroup
	errorsSeen := make(chan struct{}, 1)
	readers.Add(1)
	go func() {
		defer readers.Done()
		for {
			select {
			case <-stop:
				return
			default:
				state, err := managedstate.Read(path)
				if err != nil && !errors.Is(err, managedstate.ErrStateChanged) || err == nil && managedstate.Validate(state) != nil {
					select {
					case errorsSeen <- struct{}{}:
					default:
					}
					return
				}
			}
		}
	}()
	for index := 0; index < 20; index++ {
		next := store.Snapshot()
		next.Revision++
		next.Resources[0].Fingerprint = fmt.Sprintf("%064x", index+1)
		if err := store.Save(next); err != nil {
			close(stop)
			readers.Wait()
			t.Fatal("could not publish a concurrent checkpoint")
		}
	}
	close(stop)
	readers.Wait()
	select {
	case <-errorsSeen:
		t.Error("concurrent reader observed partial or malformed checkpoint bytes")
	default:
	}
	loaded, err := managedstate.Read(path)
	if err != nil || loaded.Revision != 21 || !sort.SliceIsSorted(loaded.Resources, func(i, j int) bool { return loaded.Resources[i].ID < loaded.Resources[j].ID }) {
		t.Error("concurrent checkpoint publication lost a revision or canonical ordering")
	}
}

var _ io.Reader = stateFailedReader{}
