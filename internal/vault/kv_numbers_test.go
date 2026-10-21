package vault_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func assertKVNumberRejected(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, vault.ErrInvalidData) {
		t.Errorf("unsafe KV v2 number error = %v, want invalid data", err)
	}
	assertKVSafeError(t, err)
	if !strings.Contains(strings.ToLower(err.Error()), "string") {
		t.Error("unsafe number error did not explain the string representation option")
	}
	for _, number := range []string{"9007199254740993", "0.10000000000000000001", "1e309", "1e-400"} {
		if strings.Contains(err.Error(), number) {
			t.Error("unsafe number error exposed the rejected secret value")
		}
	}
}

func TestPutKV2RejectsNumbersThatVaultWouldChangeBeforeAnyMutation(t *testing.T) {
	for _, test := range []struct {
		name  string
		value any
	}{
		{name: "large odd integer", value: json.Number("9007199254740993")},
		{name: "typed large integer", value: int64(9007199254740993)},
		{name: "long decimal", value: json.Number("0.10000000000000000001")},
		{name: "overflow", value: json.Number("1e309")},
		{name: "underflow", value: json.Number("1e-400")},
		{name: "nested object", value: map[string]any{"private": json.Number("9007199254740993")}},
		{name: "nested array", value: []any{true, map[string]any{"private": []any{json.Number("0.10000000000000000001")}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			})
			_, err := client.Put(context.Background(), "selected-token", "/secret/app", map[string]any{"value": test.value}, vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret", Version: 2}})
			assertKVNumberRejected(t, err)
			if requests.Load() != 0 {
				t.Error("unsafe KV v2 data performed a request despite an explicit mount")
			}
		})
	}
}

func TestPutKV2AcceptsNumbersWithUnchangedMathematicalJSONValuesAndStrings(t *testing.T) {
	values := map[string]any{
		"large_even": json.Number("9007199254740994"),
		"decimal":    json.Number("0.1"),
		"whole":      json.Number("1.0"),
		"strings":    []any{"9007199254740993", "0.10000000000000000001", "1e309", "1e-400"},
		"nested":     map[string]any{"values": []any{json.Number("0.1"), json.Number("1.0"), json.Number("9007199254740994")}},
	}
	var writes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		assertKVWriteCredentials(t, r, "selected-token")
		if r.URL.Path != "/v1/secret/data/app" {
			t.Error("valid numeric write used an unexpected route")
		}
		want := map[string]any{"data": values, "options": map[string]any{"cas": json.Number("0")}}
		if !reflect.DeepEqual(kvWriteBody(t, r), want) {
			t.Error("valid numeric write changed values or silently converted numbers to strings")
		}
		kvReply(w, map[string]any{"version": 1})
	})
	_, err := client.Put(context.Background(), "selected-token", "/secret/app", values, vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/secret", Version: 2}})
	if err != nil {
		t.Fatalf("write values Vault can preserve: %v", err)
	}
	if writes.Load() != 1 {
		t.Errorf("valid numeric mutation requests = %d, want one", writes.Load())
	}
}

func TestPutKV1PreservesArbitraryJSONNumberTextOnTheWire(t *testing.T) {
	values := map[string]any{
		"large":   json.Number("9007199254740993123456789"),
		"decimal": json.Number("0.10000000000000000001"),
		"nested":  []any{map[string]any{"overflow": json.Number("1e309"), "underflow": json.Number("1e-400")}},
	}
	var writes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		if r.URL.Path != "/v1/legacy/app" || !reflect.DeepEqual(kvWriteBody(t, r), values) {
			t.Error("KV v1 write lost arbitrary JSON number precision or added a KV v2 envelope")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	_, err := client.Put(context.Background(), "selected-token", "/legacy/app", values, vault.WriteOptions{KVOptions: vault.KVOptions{Mount: "/legacy", Version: 1}})
	if err != nil {
		t.Fatalf("write exact KV v1 JSON numbers: %v", err)
	}
	if writes.Load() != 1 {
		t.Errorf("KV v1 exact numeric writes = %d, want one", writes.Load())
	}
}

func TestCopyAndMoveToKV2RejectUnsafeNumbersWithoutChangingEitherPath(t *testing.T) {
	for _, number := range []json.Number{"9007199254740993", "0.10000000000000000001", "1e309", "1e-400"} {
		for _, sourceKV := range []string{"1", "2"} {
			for _, move := range []bool{false, true} {
				name := "copy"
				if move {
					name = "move"
				}
				t.Run(name+" from KV"+sourceKV+" with "+number.String(), func(t *testing.T) {
					var mutations, sourceReads atomic.Int32
					values := map[string]any{"nested": []any{map[string]any{"value": number}}}
					client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
						assertKVWriteCredentials(t, r, "selected-token")
						if r.Method != http.MethodGet {
							mutations.Add(1)
							t.Error("unsafe copied values changed the destination or deleted the source")
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
						switch r.URL.Path {
						case "/v1/sys/internal/ui/mounts/source/app":
							kvReply(w, kvMountMetadata("source/", sourceKV))
						case "/v1/sys/internal/ui/mounts/destination/app":
							kvReply(w, kvMountMetadata("destination/", "2"))
						case "/v1/source/app", "/v1/source/data/app":
							sourceReads.Add(1)
							if sourceKV == "1" {
								kvReply(w, values)
							} else {
								kvReply(w, map[string]any{"data": values, "metadata": map[string]any{"version": 7}})
							}
						default:
							t.Errorf("unexpected request while checking numeric copy safety: %s", r.URL.Path)
							w.WriteHeader(http.StatusNotFound)
						}
					})
					var err error
					if move {
						_, err = client.Move(context.Background(), "selected-token", "/source/app", "/destination/app", vault.WriteOptions{Force: sourceKV == "1"})
					} else {
						_, err = client.Copy(context.Background(), "selected-token", "/source/app", "/destination/app", vault.WriteOptions{})
					}
					assertKVNumberRejected(t, err)
					if errors.Is(err, vault.ErrPartial) || mutations.Load() != 0 || sourceReads.Load() != 1 {
						t.Error("unsafe numeric transfer was partial, skipped the source, or attempted a mutation")
					}
				})
			}
		}
	}
}

func TestRollbackToKV2RejectsUnsafeHistoricalNumbersBeforeWriting(t *testing.T) {
	var writes atomic.Int32
	client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writes.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/v1/secret/metadata/app" {
			kvReply(w, map[string]any{"current_version": 4, "oldest_version": 1, "versions": map[string]any{}})
		} else {
			kvReply(w, map[string]any{"data": map[string]any{"nested": []any{json.Number("9007199254740993")}}, "metadata": map[string]any{"version": 2}})
		}
	})
	_, err := client.Rollback(context.Background(), "selected-token", "/secret/app", 2, vault.KVOptions{Mount: "/secret", Version: 2})
	assertKVNumberRejected(t, err)
	if writes.Load() != 0 {
		t.Error("unsafe historical values were written into a new revision")
	}
}
