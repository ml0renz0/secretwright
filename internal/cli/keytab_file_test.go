package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/keytab"
)

var keytabIOKey = bytes.Repeat([]byte{0xa7}, 32)

func keytabIOBinary(t *testing.T, enctype uint16, key []byte) []byte {
	t.Helper()
	var entry bytes.Buffer
	write := func(value any) {
		if binary.Write(&entry, binary.BigEndian, value) != nil {
			t.Fatal("could not encode native keytab file fixture")
		}
	}
	text := func(value string) {
		write(uint16(len(value)))
		entry.WriteString(value)
	}
	write(uint16(2))
	text("EXAMPLE.TEST")
	text("HTTP")
	text("app.example.test")
	write(uint32(2))
	write(uint32(0xe1234567))
	write(uint8(3))
	write(enctype)
	write(uint16(len(key)))
	entry.Write(key)
	write(uint32(259))
	entry.Write([]byte{0xde, 0xad, 0xbe})
	var file bytes.Buffer
	file.Write([]byte{5, 2})
	if binary.Write(&file, binary.BigEndian, int32(-4)) != nil {
		t.Fatal("could not encode native keytab hole fixture")
	}
	file.WriteString("hole")
	if binary.Write(&file, binary.BigEndian, int32(entry.Len())) != nil {
		t.Fatal("could not encode native keytab record fixture")
	}
	file.Write(entry.Bytes())
	file.Write(make([]byte, 12))
	return file.Bytes()
}

func keytabIOFixture(t *testing.T) []byte {
	t.Helper()
	return keytabIOBinary(t, 18, keytabIOKey)
}

func keytabIOFile(t *testing.T, body []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private-keytab-file-marker")
	if os.WriteFile(path, body, 0o600) != nil || os.Chmod(path, mode) != nil {
		t.Fatal("could not prepare native keytab file fixture")
	}
	return path
}

func keytabIOError(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("unsafe keytab file operation succeeded")
	}
	markers := append(forbidden, "private-keytab-file-marker", "private-keytab-policy-marker", string(keytabIOKey), base64.StdEncoding.EncodeToString(keytabIOKey))
	for _, marker := range markers {
		if marker != "" && strings.Contains(err.Error(), marker) {
			t.Error("keytab file error exposed a filename, policy value or key")
		}
	}
}

func TestKeytabPrivateReaderPreservesTheOriginalBinaryAndAcceptedProfiles(t *testing.T) {
	for _, body := range [][]byte{
		keytabIOFixture(t),
		keytabIOBinary(t, 23, bytes.Repeat([]byte{0xc3}, 16)),
		keytabIOBinary(t, 60001, bytes.Repeat([]byte{0xd4}, 16)),
		{5, 2},
		append([]byte{5, 2}, make([]byte, (1<<20)-2)...),
	} {
		path := keytabIOFile(t, body, 0o600)
		got, err := readKeytabFile(path)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatal("keytab reader changed binary bytes or applied an undeclared policy")
		}
		got[0] ^= 0xff
		again, err := readKeytabFile(path)
		if err != nil || !bytes.Equal(again, body) {
			t.Error("mutating returned binary changed the original file or a shared buffer")
		}
	}
}

func TestKeytabPrivateReaderRejectsUnsafePermissionsAndPaths(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o640, 0o644, 0o660, 0o700, 0o777, 0o600 | os.ModeSetuid, 0o600 | os.ModeSetgid, 0o600 | os.ModeSticky} {
		path := keytabIOFile(t, keytabIOFixture(t), mode)
		body, err := readKeytabFile(path)
		keytabIOError(t, err, path)
		if len(body) != 0 {
			t.Error("unprotected keytab input returned private bytes")
		}
	}
	regular := keytabIOFile(t, keytabIOFixture(t), 0o600)
	link := filepath.Join(t.TempDir(), "private-keytab-file-marker-link")
	broken := filepath.Join(t.TempDir(), "private-keytab-file-marker-dangling")
	if os.Symlink(regular, link) != nil || os.Symlink(regular+".missing", broken) != nil {
		t.Fatal("could not prepare keytab symlink fixtures")
	}
	for _, path := range []string{"", "-", regular + ".missing", t.TempDir(), link, broken, "private-keytab-file-marker\n", string([]byte{0xff}), "\x00"} {
		body, err := readKeytabFile(path)
		keytabIOError(t, err, path)
		if len(body) != 0 {
			t.Error("unsafe keytab path returned private bytes")
		}
	}
}

func TestKeytabPrivateReaderRejectsMalformedOrOversizedBinaryWithoutPartialBytes(t *testing.T) {
	valid := keytabIOFixture(t)
	for _, body := range [][]byte{
		nil,
		[]byte("private-keytab-file-marker"),
		{5},
		{5, 1},
		{5, 2, 0, 0, 0},
		valid[:len(valid)-13],
		keytabIOBinary(t, 18, []byte("private-keytab-policy-marker")),
		append([]byte{5, 2}, make([]byte, (1<<20)-1)...),
	} {
		path := keytabIOFile(t, body, 0o600)
		got, err := readKeytabFile(path)
		keytabIOError(t, err, path)
		if len(got) != 0 {
			t.Error("invalid keytab input returned partial private bytes")
		}
	}
}

const keytabIOPolicy = `api_version: secretwright/keytab/v1
name: web
principal:
  realm: EXAMPLE.TEST
  components: [HTTP, app.example.test]
minimum_kvno: 3
allowed_enctypes: [17, 18, 19, 20]
required_enctypes: [18]
allow_other_principals: false
`

func TestKeytabPolicyReaderAllowsPublicConfigurationAndRejectsAmbiguity(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o644} {
		path := keytabIOFile(t, []byte(keytabIOPolicy), mode)
		policy, err := readKeytabPolicy(path)
		if err != nil || policy.APIVersion != keytab.APIVersion || policy.Name != "web" || policy.Principal.Realm != "EXAMPLE.TEST" || !reflect.DeepEqual(policy.Principal.Components, []string{"HTTP", "app.example.test"}) || policy.MinimumKVNO != 3 {
			t.Fatal("public structured keytab policy could not be loaded")
		}
		policy.Principal.Components[0] = "changed"
		again, err := readKeytabPolicy(path)
		if err != nil || again.Principal.Components[0] != "HTTP" {
			t.Error("returned policy components shared state with a subsequent read")
		}
	}
	for _, body := range [][]byte{
		nil,
		[]byte(keytabIOPolicy + "private-keytab-policy-marker: true\n"),
		[]byte(keytabIOPolicy + "---\nprivate-keytab-policy-marker: true\n"),
		[]byte(strings.Replace(keytabIOPolicy, "name: web", "name: web\nname: private-keytab-policy-marker", 1)),
		[]byte(strings.Replace(keytabIOPolicy, "components: [HTTP, app.example.test]", "components: &private-keytab-policy-marker [HTTP, app.example.test]", 1)),
		bytes.Repeat([]byte(" "), (1<<20)+1),
	} {
		path := keytabIOFile(t, body, 0o644)
		policy, err := readKeytabPolicy(path)
		keytabIOError(t, err, path)
		if !reflect.DeepEqual(policy, keytab.Policy{}) {
			t.Error("invalid keytab policy returned partial configuration")
		}
	}
	regular := keytabIOFile(t, []byte(keytabIOPolicy), 0o644)
	link := filepath.Join(t.TempDir(), "private-keytab-file-marker-policy-link")
	if os.Symlink(regular, link) != nil {
		t.Fatal("could not prepare keytab policy symlink")
	}
	for _, path := range []string{"", "-", regular + ".missing", t.TempDir(), link} {
		policy, err := readKeytabPolicy(path)
		keytabIOError(t, err, path)
		if !reflect.DeepEqual(policy, keytab.Policy{}) {
			t.Error("unsafe policy path returned partial configuration")
		}
	}
}

func TestKeytabOutputReservesOnceAndRetainsExactPrivateBinaryAfterCommit(t *testing.T) {
	body := keytabIOFixture(t)
	path := filepath.Join(t.TempDir(), "private-keytab-file-marker-output")
	output, err := reserveKeytabOutput(path)
	if err != nil {
		t.Fatal("could not reserve private keytab output")
	}
	defer output.abort()
	if again, err := reserveKeytabOutput(path); !errors.Is(err, errKeytabOutputConflict) || again != nil {
		t.Error("keytab output reservation was not exclusive")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode() != 0o600 || info.Size() != 0 {
		t.Fatal("keytab reservation was not an empty private regular file")
	}
	if err := commitKeytabOutput(output, body); err != nil {
		t.Fatal("could not publish keytab output")
	}
	output.abort()
	got, err := os.ReadFile(path)
	info, statErr := os.Lstat(path)
	if err != nil || statErr != nil || info.Mode() != 0o600 || !bytes.Equal(got, body) {
		t.Error("committed keytab binary or its private permissions were not preserved")
	}
}

func TestKeytabOutputRefusesExistingForeignPathsAndUnsafeReservations(t *testing.T) {
	foreign := []byte("private-keytab-policy-marker")
	existing := keytabIOFile(t, foreign, 0o600)
	link := filepath.Join(t.TempDir(), "private-keytab-file-marker-output-link")
	if os.Symlink(existing, link) != nil {
		t.Fatal("could not prepare foreign output symlink")
	}
	for _, path := range []string{existing, link, t.TempDir()} {
		output, err := reserveKeytabOutput(path)
		if output != nil || !errors.Is(err, errKeytabOutputConflict) {
			t.Error("existing keytab output path was not reported as a conflict")
		}
		keytabIOError(t, err, path)
	}
	for _, path := range []string{"", "-", "\x00", filepath.Join(t.TempDir(), "private-keytab-file-marker\n")} {
		output, err := reserveKeytabOutput(path)
		keytabIOError(t, err, path)
		if output != nil {
			output.abort()
			t.Error("unsafe keytab output name acquired a reservation")
		}
	}
	if got, err := os.ReadFile(existing); err != nil || !bytes.Equal(got, foreign) {
		t.Error("keytab output validation modified a foreign file")
	}
}

func TestKeytabPublicationRejectsMalformedBinaryBeforeWriting(t *testing.T) {
	for _, body := range [][]byte{
		nil,
		[]byte("private-keytab-policy-marker"),
		{5, 1},
		append([]byte{5, 2}, make([]byte, (1<<20)-1)...),
	} {
		path := filepath.Join(t.TempDir(), "private-keytab-file-marker-output")
		output, err := reserveKeytabOutput(path)
		if err != nil {
			t.Fatal("could not reserve malformed-output fixture")
		}
		err = commitKeytabOutput(output, body)
		keytabIOError(t, err, path)
		info, statErr := os.Lstat(path)
		if output.committed || statErr != nil || info.Size() != 0 {
			t.Error("malformed binary was written or marked as a published keytab")
		}
		output.abort()
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Error("malformed own reservation survived cleanup")
		}
	}
}

func TestKeytabPublicationRechecksTheReservedInodeAndPrivateMode(t *testing.T) {
	for _, change := range []string{"replacement", "symlink", "mode", "closed"} {
		t.Run(change, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private-keytab-file-marker-output")
			output, err := reserveKeytabOutput(path)
			if err != nil {
				t.Fatal("could not reserve output proof fixture")
			}
			defer output.abort()
			foreign := []byte("private-keytab-policy-marker")
			target := filepath.Join(t.TempDir(), "foreign-keytab-output")
			switch change {
			case "replacement":
				if os.Remove(path) != nil || os.WriteFile(path, foreign, 0o600) != nil {
					t.Fatal("could not replace reserved keytab inode")
				}
			case "symlink":
				if os.WriteFile(target, foreign, 0o600) != nil || os.Remove(path) != nil || os.Symlink(target, path) != nil {
					t.Fatal("could not replace reservation with a foreign symlink")
				}
			case "mode":
				if os.Chmod(path, 0o644) != nil {
					t.Fatal("could not weaken reserved file mode")
				}
			case "closed":
				if output.file.Close() != nil {
					t.Fatal("could not close reserved output descriptor")
				}
			}
			err = commitKeytabOutput(output, keytabIOFixture(t))
			keytabIOError(t, err, path)
			if output.committed {
				t.Error("failed publication was marked committed")
			}
			output.abort()
			if change == "replacement" || change == "symlink" {
				if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, foreign) {
					t.Error("publication or cleanup modified a foreign replacement")
				}
			} else if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Error("failed own reservation was not removed during cleanup")
			}
		})
	}
}
