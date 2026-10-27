package vault_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/keytab"
	"github.com/ml0renz0/secretwright/internal/vault"
	"gopkg.in/yaml.v3"
)

const keytabVaultPath = "/keytabs/services/http"

func keytabVaultOptions() vault.KVOptions {
	return vault.KVOptions{Mount: "keytabs", Version: 2}
}

// The fixture deliberately contains an opaque hole, an extended KVNO, a
// timestamp beyond 2038 and padding. A roundtrip must preserve every byte.
func nativeVaultKeytab() []byte {
	var entry bytes.Buffer
	write16 := func(value uint16) { _ = binary.Write(&entry, binary.BigEndian, value) }
	write32 := func(value uint32) { _ = binary.Write(&entry, binary.BigEndian, value) }
	text := func(value string) {
		write16(uint16(len(value)))
		_, _ = entry.WriteString(value)
	}
	write16(2)
	text("EXAMPLE.TEST")
	text("HTTP")
	text("app.example.test")
	write32(2)
	write32(0x80000001)
	_ = entry.WriteByte(3)
	write16(18)
	write16(32)
	_, _ = entry.Write(bytes.Repeat([]byte{0xa6}, 32))
	write32(260)
	_, _ = entry.Write([]byte{0xfa, 0xfb})
	var output bytes.Buffer
	_, _ = output.Write([]byte{5, 2})
	_ = binary.Write(&output, binary.BigEndian, int32(-5))
	_, _ = output.Write([]byte{0xde, 0xad, 0xbe, 0xef, 0})
	_ = binary.Write(&output, binary.BigEndian, int32(entry.Len()))
	_, _ = output.Write(entry.Bytes())
	_, _ = output.Write(make([]byte, 6))
	return output.Bytes()
}

func nativeVaultKeytabEnvelope(body []byte) map[string]any {
	return map[string]any{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": base64.StdEncoding.EncodeToString(body)}
}

func keytabVaultSafe(t *testing.T, value any) {
	t.Helper()
	var body []byte
	if failure, ok := value.(error); ok {
		if failure == nil {
			t.Fatal("expected a safe keytab operation error")
		}
		body = []byte(failure.Error())
	} else {
		var err error
		body, err = json.Marshal(value)
		if err != nil {
			t.Fatal("could not encode keytab metadata")
		}
		encodedYAML, err := yaml.Marshal(value)
		if err != nil {
			t.Fatal("could not encode keytab metadata as YAML")
		}
		body = append(body, encodedYAML...)
	}
	key := bytes.Repeat([]byte{0xa6}, 32)
	for _, secret := range []string{
		"selected-token", "private-f12-upstream", base64.StdEncoding.EncodeToString(nativeVaultKeytab()),
		base64.StdEncoding.EncodeToString(key), hex.EncodeToString(key), string(key),
	} {
		if bytes.Contains(body, []byte(secret)) {
			t.Error("keytab report or error exposed authentication or key material")
		}
	}
}

func TestKeytabStorageUsesOnlyExplicitKV2DataAndExactCAS(t *testing.T) {
	seven := 7
	zero := 0
	for _, cas := range []*int{nil, &zero, &seven} {
		var requests atomic.Int32
		raw := nativeVaultKeytab()
		before := append([]byte(nil), raw...)
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			assertKVWriteCredentials(t, r, "selected-token")
			if r.Method != http.MethodPost || r.URL.Path != "/v1/keytabs/data/services/http" || r.URL.RawQuery != "" {
				t.Error("keytab import performed discovery, changed its exact target or selected KV v1")
			}
			expectedCAS := json.Number("0")
			if cas != nil && *cas == 7 {
				expectedCAS = "7"
			}
			want := map[string]any{"data": nativeVaultKeytabEnvelope(raw), "options": map[string]any{"cas": expectedCAS}}
			if !reflect.DeepEqual(kvWriteBody(t, r), want) {
				t.Error("keytab import changed its binary envelope or explicit CAS")
			}
			kvReply(w, map[string]any{"version": 9})
		})
		written, err := client.StoreKeytab(context.Background(), "selected-token", keytabVaultPath, raw, cas, keytabVaultOptions())
		if err != nil || written.Path != keytabVaultPath || written.KVVersion != 2 || written.Version != 9 || requests.Load() != 1 || !bytes.Equal(before, raw) {
			t.Fatal("keytab import failed to report its confirmed CAS-protected version")
		}
		keytabVaultSafe(t, written)
	}
}

func TestKeytabReadsReturnExactBytesAndTheVersionFromTheSameResponse(t *testing.T) {
	for _, requested := range []int{0, 3} {
		var requests atomic.Int32
		raw := nativeVaultKeytab()
		actual := requested
		if actual == 0 {
			actual = 11
		}
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			assertKVReadOnlyRequest(t, r, "selected-token")
			if r.URL.Path != "/v1/keytabs/data/services/http" || requested == 0 && r.URL.RawQuery != "" || requested == 3 && r.URL.Query().Get("version") != "3" {
				t.Error("keytab read fetched a different revision or performed a metadata/discovery request")
			}
			kvReply(w, map[string]any{"data": nativeVaultKeytabEnvelope(raw), "metadata": map[string]any{"version": actual}})
		})
		read, err := client.ReadKeytab(context.Background(), "selected-token", keytabVaultPath, requested, keytabVaultOptions())
		if err != nil || !bytes.Equal(read.Data, raw) || read.Path != keytabVaultPath || read.Version != actual || read.Report.Version != 2 || read.Report.Holes != 1 || len(read.Report.Entries) != 1 || read.Report.Entries[0].KVNO != 260 || read.Report.AuthenticationChecked || requests.Load() != 1 {
			t.Fatal("keytab read changed private bytes, metadata, or the exact captured revision")
		}
		keytabVaultSafe(t, read)
		read.Data[0] = 0
		if raw[0] != 5 {
			t.Error("returned keytab bytes aliased the caller's source buffer")
		}
	}
}

func TestKeytabLocalPreflightRejectsInvalidBinaryTargetCASAndVersionBeforeHTTP(t *testing.T) {
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	for _, test := range []struct {
		path string
		opts vault.KVOptions
	}{
		{"relative/key", keytabVaultOptions()}, {"/keytabs", keytabVaultOptions()},
		{"/keytabs-other/key", keytabVaultOptions()}, {"/keytabs/../foreign/key", keytabVaultOptions()},
		{"/keytabs//key", keytabVaultOptions()}, {"/keytabs/private?key", keytabVaultOptions()},
		{"/keytabs/key", vault.KVOptions{Version: 2}},
		{"/keytabs/key", vault.KVOptions{Mount: "keytabs", Version: 1}},
		{"/keytabs/key", vault.KVOptions{Mount: "keytabs", Version: 2, CWD: "/keytabs"}},
		{"/keytabs/key", vault.KVOptions{Mount: "../keytabs", Version: 2}},
	} {
		if vault.ValidateKeytabTarget(test.path, test.opts) == nil {
			t.Error("unsafe keytab target passed standalone validation")
		}
		if _, err := client.StoreKeytab(context.Background(), "", test.path, nativeVaultKeytab(), nil, test.opts); err == nil {
			t.Error("keytab import bypassed target preflight")
		}
		if _, err := client.ReadKeytab(context.Background(), "", test.path, 0, test.opts); err == nil {
			t.Error("keytab export bypassed target preflight")
		}
	}
	for _, raw := range [][]byte{nil, {}, {5, 1}, {5, 2, 0, 0, 0, 9, 1}, bytes.Repeat([]byte{5}, (1<<20)+1)} {
		if _, err := client.StoreKeytab(context.Background(), "", keytabVaultPath, raw, nil, keytabVaultOptions()); !errors.Is(err, keytab.ErrInvalidInput) {
			t.Error("malformed keytab was not rejected before selecting credentials")
		} else {
			keytabVaultSafe(t, err)
		}
	}
	negative := -1
	if _, err := client.StoreKeytab(context.Background(), "", keytabVaultPath, nativeVaultKeytab(), &negative, keytabVaultOptions()); err == nil {
		t.Error("negative CAS was accepted")
	}
	if _, err := client.ReadKeytab(context.Background(), "", keytabVaultPath, -1, keytabVaultOptions()); err == nil || requests.Load() != 0 {
		t.Error("invalid keytab options contacted Vault")
	}
}

func TestKeytabExportRejectsAmbiguousOrNoncanonicalSensitiveEnvelopes(t *testing.T) {
	raw := nativeVaultKeytab()
	encoded := base64.StdEncoding.EncodeToString(raw)
	for _, envelope := range []map[string]any{
		{}, {"api_version": "foreign/keytab/v1", "encoding": "base64", "data": encoded},
		{"api_version": "secretwright/keytab/v1", "encoding": "hex", "data": encoded},
		{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": encoded, "private": "private-f12-upstream"},
		{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": nil},
		{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": 17},
		{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": encoded + "\n"},
		{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": encoded[:len(encoded)-1]},
		{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": "BQJ="},
		{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": base64.StdEncoding.EncodeToString([]byte{5, 1})},
		{"api_version": "secretwright/keytab/v1", "encoding": "base64", "data": strings.Repeat("A", ((1<<20)*4/3)+12)},
	} {
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			kvReply(w, map[string]any{"data": envelope, "metadata": map[string]any{"version": 1}})
		})
		read, err := client.ReadKeytab(context.Background(), "selected-token", keytabVaultPath, 0, keytabVaultOptions())
		if err == nil || len(read.Data) != 0 || len(read.Report.Entries) != 0 {
			t.Error("invalid Vault envelope returned partial key material or metadata")
		} else {
			keytabVaultSafe(t, err)
		}
		keytabVaultSafe(t, read)
	}
}

func TestKeytabReadRequiresExactPositiveRevisionMetadataAndNeverFallsBack(t *testing.T) {
	for _, test := range []struct {
		status   int
		data     any
		metadata any
		missing  bool
	}{
		{200, nativeVaultKeytabEnvelope(nativeVaultKeytab()), nil, false},
		{200, nativeVaultKeytabEnvelope(nativeVaultKeytab()), map[string]any{"version": 0}, false},
		{200, nativeVaultKeytabEnvelope(nativeVaultKeytab()), map[string]any{"version": "private-f12-upstream"}, false},
		{200, nativeVaultKeytabEnvelope(nativeVaultKeytab()), map[string]any{"version": 4}, false},
		{200, nil, map[string]any{"version": 3}, true},
		{404, nativeVaultKeytabEnvelope(nativeVaultKeytab()), map[string]any{"version": 3, "destroyed": true}, true},
	} {
		var requests atomic.Int32
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.WriteHeader(test.status)
			kvReply(w, map[string]any{"data": test.data, "metadata": test.metadata})
		})
		read, err := client.ReadKeytab(context.Background(), "selected-token", keytabVaultPath, 3, keytabVaultOptions())
		if err == nil || len(read.Data) != 0 || requests.Load() != 1 || test.missing && !errors.Is(err, vault.ErrNotFound) {
			t.Error("invalid or deleted keytab revision succeeded or caused a fallback lookup")
		}
		keytabVaultSafe(t, read)
		if err != nil {
			keytabVaultSafe(t, err)
		}
	}
}

func TestKeytabReadCapsTheHTTPBodyBeforeParsingSuccessfulJSON(t *testing.T) {
	valid, err := json.Marshal(map[string]any{"data": map[string]any{"data": nativeVaultKeytabEnvelope(nativeVaultKeytab()), "metadata": map[string]any{"version": 1}}})
	if err != nil {
		t.Fatal("could not encode bounded-response fixture")
	}
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat(" ", 2<<20))
		_, _ = w.Write(valid)
	})
	read, err := client.ReadKeytab(context.Background(), "selected-token", keytabVaultPath, 0, keytabVaultOptions())
	if err == nil || len(read.Data) != 0 {
		t.Error("an oversized successful HTTP response reached the keytab decoder")
	} else {
		keytabVaultSafe(t, err)
	}
}

func TestKeytabReadPreservesDeniedAndMissingWithoutClaimingMutationUncertainty(t *testing.T) {
	for _, test := range []struct {
		status int
		want   error
	}{
		{403, vault.ErrPermissionDenied}, {404, vault.ErrNotFound}, {503, nil},
	} {
		var requests atomic.Int32
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			w.WriteHeader(test.status)
			_, _ = io.WriteString(w, `{"errors":["private-f12-upstream"]}`)
		})
		read, err := client.ReadKeytab(context.Background(), "selected-token", keytabVaultPath, 0, keytabVaultOptions())
		if err == nil || test.want != nil && !errors.Is(err, test.want) || errors.Is(err, vault.ErrAccessUnconfirmed) || len(read.Data) != 0 || requests.Load() != 1 {
			t.Error("read-only keytab failure was retried, leaked data or changed its status")
		}
		if err != nil {
			keytabVaultSafe(t, err)
		}
	}
}

func TestKeytabReadCancellationAfterHeadersReturnsNoPartialKeytabOrRetry(t *testing.T) {
	started := make(chan struct{})
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"data":`)
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type result struct {
		stored vault.StoredKeytab
		err    error
	}
	done := make(chan result, 1)
	go func() {
		stored, err := client.ReadKeytab(ctx, "selected-token", keytabVaultPath, 0, keytabVaultOptions())
		done <- result{stored: stored, err: err}
	}()
	select {
	case <-started:
	case <-done:
		t.Fatal("keytab response completed before the cancellation fixture was ready")
	}
	cancel()
	got := <-done
	if !errors.Is(got.err, context.Canceled) || errors.Is(got.err, vault.ErrAccessUnconfirmed) || requests.Load() != 1 || len(got.stored.Data) != 0 || len(got.stored.Report.Entries) != 0 {
		t.Error("cancellation during the keytab response lost its status, retried or exposed partial credentials")
	}
	keytabVaultSafe(t, got.stored)
	if got.err != nil {
		keytabVaultSafe(t, got.err)
	}
}

func TestKeytabImportNeverRetriesOrCompensatesUnknownWriteOutcomes(t *testing.T) {
	for _, outcome := range []string{"lost", "malformed", "missing version", "server failure"} {
		var writes atomic.Int32
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			writes.Add(1)
			if r.Method != http.MethodPost || r.URL.Path != "/v1/keytabs/data/services/http" {
				t.Error("keytab import performed a retry, cleanup or discovery operation")
			}
			switch outcome {
			case "lost":
				loseKVMutationResponse(t, w)
			case "malformed":
				_, _ = io.WriteString(w, `{"data":{"version":1}`)
			case "missing version":
				kvReply(w, map[string]any{"private": "private-f12-upstream"})
			case "server failure":
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = io.WriteString(w, `{"errors":["private-f12-upstream"]}`)
			}
		})
		written, err := client.StoreKeytab(context.Background(), "selected-token", keytabVaultPath, nativeVaultKeytab(), nil, keytabVaultOptions())
		if !errors.Is(err, vault.ErrAccessUnconfirmed) || writes.Load() != 1 {
			t.Error("unknown keytab mutation was retried or lost its exported uncertainty sentinel")
		}
		keytabVaultSafe(t, written)
		if err != nil {
			keytabVaultSafe(t, err)
		}
	}
}

func TestKeytabImportKeepsCASAndPermissionDenialsDefinite(t *testing.T) {
	for _, test := range []struct {
		status  int
		message string
		want    error
	}{
		{400, "check-and-set parameter did not match the current version", vault.ErrConflict},
		{403, "private-f12-upstream", vault.ErrPermissionDenied},
	} {
		client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(test.status)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{test.message}})
		})
		_, err := client.StoreKeytab(context.Background(), "selected-token", keytabVaultPath, nativeVaultKeytab(), nil, keytabVaultOptions())
		if !errors.Is(err, test.want) || errors.Is(err, vault.ErrAccessUnconfirmed) {
			t.Error("definite keytab rejection appeared uncertain or lost its typed status")
		}
		if err != nil {
			keytabVaultSafe(t, err)
		}
	}
}

func TestKeytabCanceledBeforeStartingDoesNotSelectCredentialsOrMakeRequests(t *testing.T) {
	var requests atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.StoreKeytab(ctx, "", keytabVaultPath, nativeVaultKeytab(), nil, keytabVaultOptions())
	if !errors.Is(err, context.Canceled) || errors.Is(err, vault.ErrAccessUnconfirmed) || requests.Load() != 0 {
		t.Error("pre-canceled keytab import attempted a credential selection or mutation")
	}
	if _, err := client.ReadKeytab(ctx, "", keytabVaultPath, 0, keytabVaultOptions()); !errors.Is(err, context.Canceled) || requests.Load() != 0 {
		t.Error("pre-canceled keytab export selected credentials or made a request")
	}
}
