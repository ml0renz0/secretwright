//go:build integration

package vault_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ml0renz0/secretwright/internal/keytab"
	"github.com/ml0renz0/secretwright/internal/vault"
)

type keytabIntegrationFixture struct {
	admin     *api.Client
	client    *vault.Client
	mount     string
	token     string
	readOnly  string
	writeOnly string
	denied    string
}

func prepareKeytabIntegration(t *testing.T) keytabIntegrationFixture {
	t.Helper()
	admin := integrationTokenAdmin(t)
	client, err := vault.NewFromEnvironment()
	if err != nil {
		t.Fatal("could not create the disposable keytab client")
	}
	f := keytabIntegrationFixture{admin: admin, client: client, mount: fmt.Sprintf("secretwright-f12-%d", time.Now().UnixNano())}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := admin.Sys().MountWithContext(ctx, f.mount, &api.MountInput{Type: "kv", Options: map[string]string{"version": "2"}}); err != nil {
		t.Fatal("could not mount the disposable keytab KV v2 engine")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = admin.Sys().UnmountWithContext(cleanup, f.mount)
	})
	path := f.mount + "/data/allowed/*"
	f.token = createKVIntegrationPolicyToken(t, admin, f.mount+"-read-write", fmt.Sprintf(`path %q { capabilities = ["create", "update", "read"] }`, path))
	f.readOnly = createKVIntegrationPolicyToken(t, admin, f.mount+"-read", fmt.Sprintf(`path %q { capabilities = ["read"] }`, path))
	f.writeOnly = createKVIntegrationPolicyToken(t, admin, f.mount+"-write", fmt.Sprintf(`path %q { capabilities = ["create", "update"] }`, path))
	f.denied = createKVIntegrationPolicyToken(t, admin, f.mount+"-denied", `path "secretwright-f12-unrelated/*" { capabilities = ["read"] }`)
	return f
}

// These are native keytab bytes, including an opaque deleted record and
// padding. Export must retain those bytes rather than regenerate entries.
func keytabIntegrationBytes(kvno uint32, fill byte) ([]byte, []byte) {
	var entry bytes.Buffer
	counted := func(value string) {
		_ = binary.Write(&entry, binary.BigEndian, uint16(len(value)))
		_, _ = entry.WriteString(value)
	}
	_ = binary.Write(&entry, binary.BigEndian, uint16(2))
	counted("EXAMPLE.TEST")
	counted("HTTP")
	counted("app.fixture.test")
	_ = binary.Write(&entry, binary.BigEndian, uint32(2))
	_ = binary.Write(&entry, binary.BigEndian, uint32(0x90000000))
	_ = entry.WriteByte(3)
	_ = binary.Write(&entry, binary.BigEndian, uint16(18))
	key := bytes.Repeat([]byte{fill}, 32)
	copy(key, []byte("private-f12-key-marker-"))
	_ = binary.Write(&entry, binary.BigEndian, uint16(len(key)))
	_, _ = entry.Write(key)
	_ = binary.Write(&entry, binary.BigEndian, kvno)
	_, _ = entry.Write([]byte{0xc1, 0x72, 0x93})
	var file bytes.Buffer
	_, _ = file.Write([]byte{5, 2})
	_ = binary.Write(&file, binary.BigEndian, int32(-5))
	_, _ = file.Write([]byte{0xde, 0xad, 0x65, 0x99, 0x71})
	_ = binary.Write(&file, binary.BigEndian, int32(entry.Len()))
	_, _ = file.Write(entry.Bytes())
	_ = binary.Write(&file, binary.BigEndian, int32(0))
	_, _ = file.Write([]byte{0, 0, 0})
	return file.Bytes(), key
}

func keytabIntegrationMetadataPrivate(t *testing.T, report any, raw, key []byte, tokens ...string) {
	t.Helper()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal("could not encode keytab metadata")
	}
	fileHash, keyHash := sha256.Sum256(raw), sha256.Sum256(key)
	markers := append(tokens,
		"private-f12-key-marker-", base64.StdEncoding.EncodeToString(raw), base64.StdEncoding.EncodeToString(key),
		hex.EncodeToString(key), hex.EncodeToString(fileHash[:]), hex.EncodeToString(keyHash[:]))
	for _, marker := range markers {
		if marker != "" && bytes.Contains(body, []byte(marker)) {
			t.Error("keytab metadata exposed a key, file encoding, digest or operator credential")
		}
	}
}

func TestIntegrationKeytabKV2PreservesBinaryCASAndExactHistoricalVersions(t *testing.T) {
	f := prepareKeytabIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	opts := vault.KVOptions{Mount: f.mount, Version: 2}
	path := "/" + f.mount + "/allowed/service"
	first, firstKey := keytabIntegrationBytes(259, 'A')
	second, secondKey := keytabIntegrationBytes(260, 'B')
	written, err := f.client.StoreKeytab(ctx, f.token, path, first, nil, opts)
	if err != nil || written.Version != 1 || written.KVVersion != 2 || written.Path != path {
		t.Fatal("create-only keytab import did not return its actual KV v2 revision")
	}
	keytabIntegrationMetadataPrivate(t, written, first, firstKey, f.token)
	if _, err := f.client.StoreKeytab(ctx, f.token, path, second, nil, opts); !errors.Is(err, vault.ErrConflict) {
		t.Error("default keytab import replaced an existing secret without CAS")
	}
	cas := 1
	written, err = f.client.StoreKeytab(ctx, f.token, path, second, &cas, opts)
	if err != nil || written.Version != 2 {
		t.Fatal("explicit matching CAS did not update the keytab once")
	}
	if _, err := f.client.StoreKeytab(ctx, f.token, path, first, &cas, opts); !errors.Is(err, vault.ErrConflict) {
		t.Error("stale keytab CAS replaced a newer revision")
	}
	for _, selected := range []struct {
		version int
		actual  int
		raw     []byte
		key     []byte
		kvno    uint32
	}{{0, 2, second, secondKey, 260}, {1, 1, first, firstKey, 259}, {2, 2, second, secondKey, 260}} {
		stored, err := f.client.ReadKeytab(ctx, f.readOnly, path, selected.version, opts)
		if err != nil || stored.Version != selected.actual || stored.Path != path || !bytes.Equal(stored.Data, selected.raw) {
			t.Fatal("keytab export changed binary bytes or reported a revision from another read")
		}
		if stored.Report.AuthenticationChecked || stored.Report.Version != 2 || stored.Report.Holes != 1 || len(stored.Report.Entries) != 1 {
			t.Fatal("keytab inspection lost record metadata or falsely claimed Kerberos authentication")
		}
		entry := stored.Report.Entries[0]
		if entry.KVNO != selected.kvno || entry.Enctype != 18 || entry.KeyLength != 32 || entry.Timestamp.Unix() <= 2147483647 {
			t.Error("stored keytab metadata lost KVNO32, enctype or its post-2038 timestamp")
		}
		keytabIntegrationMetadataPrivate(t, stored, selected.raw, selected.key, f.token, f.readOnly)
	}
	if _, err := f.admin.Logical().WriteWithContext(ctx, f.mount+"/delete/allowed/service", map[string]any{"versions": []int{2}}); err != nil {
		t.Fatal("could not delete the current disposable keytab revision")
	}
	for _, revision := range []int{0, 2} {
		if stored, err := f.client.ReadKeytab(ctx, f.token, path, revision, opts); !errors.Is(err, vault.ErrNotFound) || len(stored.Data) != 0 {
			t.Error("a deleted keytab revision fell back to an older available keytab")
		}
	}
	if stored, err := f.client.ReadKeytab(ctx, f.token, path, 1, opts); err != nil || !bytes.Equal(stored.Data, first) || stored.Version != 1 {
		t.Fatal("explicit available keytab history was lost when the latest revision was deleted")
	}
	if _, err := f.admin.Logical().WriteWithContext(ctx, f.mount+"/destroy/allowed/service", map[string]any{"versions": []int{1}}); err != nil {
		t.Fatal("could not destroy the old disposable keytab revision")
	}
	if stored, err := f.client.ReadKeytab(ctx, f.token, path, 1, opts); !errors.Is(err, vault.ErrNotFound) || len(stored.Data) != 0 {
		t.Error("a destroyed keytab revision appeared available")
	}
}

func TestIntegrationKeytabAccessAndStoredEnvelopeValidationRemainEffective(t *testing.T) {
	f := prepareKeytabIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	opts := vault.KVOptions{Mount: f.mount, Version: 2}
	path := "/" + f.mount + "/allowed/service"
	raw, key := keytabIntegrationBytes(259, 'C')
	if _, err := f.client.StoreKeytab(ctx, f.writeOnly, path, raw, nil, opts); err != nil {
		t.Fatal("keytab import unexpectedly required read, discovery or token-self permissions")
	}
	if _, err := f.client.StoreKeytab(ctx, f.readOnly, "/"+f.mount+"/allowed/readonly", raw, nil, opts); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Error("a read-only token imported a keytab")
	}
	if _, err := f.client.ReadKeytab(ctx, f.denied, path, 0, opts); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Error("a token without keytab read access exported credentials")
	}
	if _, err := f.client.StoreKeytab(ctx, f.token, "/"+f.mount+"/denied/service", raw, nil, opts); !errors.Is(err, vault.ErrPermissionDenied) {
		t.Error("keytab import escaped its permitted KV subtree")
	}
	for index, envelope := range []map[string]any{
		{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": base64.StdEncoding.EncodeToString(raw), "extra": "private-f12-value"},
		{"api_version": "secretwright/keytab/v1", "encoding": "raw", "data": base64.StdEncoding.EncodeToString(raw)},
		{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": base64.StdEncoding.EncodeToString(raw) + "\n"},
		{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": base64.StdEncoding.EncodeToString([]byte{5, 1})},
	} {
		physical := fmt.Sprintf("%s/data/allowed/malformed-%d", f.mount, index)
		logical := fmt.Sprintf("/%s/allowed/malformed-%d", f.mount, index)
		if _, err := f.admin.Logical().WriteWithContext(ctx, physical, map[string]any{"data": envelope}); err != nil {
			t.Fatal("could not seed a malformed disposable keytab envelope")
		}
		stored, err := f.client.ReadKeytab(ctx, f.token, logical, 0, opts)
		if err == nil || len(stored.Data) != 0 {
			t.Error("invalid stored keytab envelope was exported as credentials")
		}
		if err != nil && strings.Contains(err.Error(), "private-f12-") {
			t.Error("stored keytab validation echoed upstream secret data")
		}
		keytabIntegrationMetadataPrivate(t, stored, raw, key, f.token)
	}
	policy := keytab.Policy{APIVersion: "secretwright/keytab/v1", Name: "application", Principal: keytab.PrincipalSpec{Realm: "EXAMPLE.TEST", Components: []string{"HTTP", "app.fixture.test"}}, MinimumKVNO: 3, AllowedEnctypes: []uint16{17, 18, 19, 20}, RequiredEnctypes: []uint16{18}}
	validated, err := keytab.Validate(bytes.NewReader(raw), policy)
	if err != nil || !validated.Valid || !validated.PolicyChecked || validated.AuthenticationChecked || validated.HighestKVNO != 259 {
		t.Error("native structural policy check failed or claimed to authenticate with a KDC")
	}
}

func TestIntegrationKeytabLostImportAcknowledgementNeverRepeatsTheWrite(t *testing.T) {
	f := prepareKeytabIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	upstream, err := url.Parse(os.Getenv("VAULT_ADDR"))
	if err != nil {
		t.Fatal("invalid disposable Vault address")
	}
	physical := "/v1/" + f.mount + "/data/allowed/uncertain"
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	proxy.ModifyResponse = func(response *http.Response) error {
		if response.Request.URL.Path == physical && response.Request.Method == http.MethodPost && response.StatusCode == http.StatusOK {
			_ = response.Body.Close()
			response.Body = io.NopCloser(strings.NewReader(`{"data":`))
			response.ContentLength = -1
			response.Header.Del("Content-Length")
		}
		return nil
	}
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == physical && r.Method == http.MethodPost {
			writes.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	address := server.URL
	client, err := vault.New(vault.Options{Address: &address})
	if err != nil {
		t.Fatal("could not create the isolated uncertain-import client")
	}
	raw, key := keytabIntegrationBytes(259, 'D')
	path, opts := "/"+f.mount+"/allowed/uncertain", vault.KVOptions{Mount: f.mount, Version: 2}
	written, err := client.StoreKeytab(ctx, f.token, path, raw, nil, opts)
	if !errors.Is(err, vault.ErrAccessUnconfirmed) || writes.Load() != 1 {
		t.Fatal("an applied keytab import with lost acknowledgement was retried or classified as definite failure")
	}
	keytabIntegrationMetadataPrivate(t, written, raw, key, f.token)
	stored, err := f.client.ReadKeytab(ctx, f.readOnly, path, 0, opts)
	if err != nil || stored.Version != 1 || !bytes.Equal(stored.Data, raw) {
		t.Fatal("the single uncertain keytab write did not retain its exact committed bytes")
	}
}
