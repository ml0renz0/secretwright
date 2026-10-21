package vault_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func loseKVMutationResponse(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		t.Error("mutation fixture cannot discard its acknowledgement")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	connection, _, err := hijacker.Hijack()
	if err != nil {
		t.Error("mutation fixture could not discard its acknowledgement")
		return
	}
	connection.Close()
}

func TestMoveUnconfirmedDestinationNeverDeletesSource(t *testing.T) {
	for _, acknowledgement := range []string{"malformed", "canceled", "lost"} {
		t.Run(acknowledgement, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var requests, sourceReads, destinationWrites, sourceDeletes atomic.Int32
			var destinationApplied atomic.Bool
			values := map[string]any{
				"value": "fixture-secret-value",
				"large": json.Number("9007199254740993123456789"),
			}
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				assertKVWriteCredentials(t, r, "selected-token")
				switch r.URL.Path {
				case "/v1/secret/data/private/path-source":
					sourceReads.Add(1)
					if r.Method != http.MethodGet {
						t.Error("unconfirmed destination caused a source mutation")
					}
					kvReply(w, map[string]any{"data": values, "metadata": map[string]any{"version": 7}})
				case "/v1/secret/data/private/path-destination":
					destinationWrites.Add(1)
					want := map[string]any{"data": values, "options": map[string]any{"cas": json.Number("0")}}
					if !reflect.DeepEqual(kvWriteBody(t, r), want) {
						t.Error("uncertain destination write changed the snapshot or create-only CAS")
					}
					// Model an applied write whose acknowledgement cannot be trusted.
					destinationApplied.Store(true)
					switch acknowledgement {
					case "malformed":
						w.Header().Set("Content-Type", "application/json")
						io.WriteString(w, `{"data":{"version":1},"upstream-private-value":"private/path"`)
					case "canceled":
						cancel()
						<-r.Context().Done()
					case "lost":
						loseKVMutationResponse(t, w)
					}
				case "/v1/secret/delete/private/path-source":
					sourceDeletes.Add(1)
					t.Error("move deleted its source without a confirmed destination")
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Error("move attempted discovery, a retry, or destination cleanup")
					w.WriteHeader(http.StatusNotFound)
				}
			})
			result, err := client.Move(ctx, "selected-token", "/secret/private/path-source", "/secret/private/path-destination", vault.WriteOptions{
				KVOptions: vault.KVOptions{Mount: "/secret", Version: 2},
			})
			assertKVSafeError(t, err)
			if errors.Is(err, vault.ErrPartial) {
				t.Error("unconfirmed destination was reported as a confirmed partial move")
			}
			if !strings.Contains(err.Error(), "not confirmed") || !strings.Contains(err.Error(), "may have applied") || !strings.Contains(err.Error(), "verify") {
				t.Error("uncertain destination did not explain how to handle its possible application")
			}
			if acknowledgement == "canceled" && !errors.Is(err, context.Canceled) {
				t.Error("uncertain destination lost its context cancellation")
			}
			if result != (vault.CopyResult{}) {
				t.Error("uncertain destination returned a confirmed copy result")
			}
			if requests.Load() != 2 || sourceReads.Load() != 1 || destinationWrites.Load() != 1 || sourceDeletes.Load() != 0 || !destinationApplied.Load() {
				t.Error("uncertain destination retried, deleted its source, or rolled back the destination")
			}
		})
	}
}

func TestMoveUnconfirmedSourceDeletionPreservesConfirmedCopy(t *testing.T) {
	for _, acknowledgement := range []string{"canceled", "lost"} {
		t.Run(acknowledgement, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var requests, sourceReads, destinationWrites, sourceDeletes atomic.Int32
			var destinationApplied, sourceDeletionApplied atomic.Bool
			values := map[string]any{
				"value": "fixture-secret-value",
				"large": json.Number("9007199254740993123456789"),
			}
			client := kvTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				assertKVWriteCredentials(t, r, "selected-token")
				switch r.URL.Path {
				case "/v1/secret/data/private/path-source":
					sourceReads.Add(1)
					if r.Method != http.MethodGet {
						t.Error("move deleted the latest source instead of its captured revision")
					}
					kvReply(w, map[string]any{"data": values, "metadata": map[string]any{"version": 7}})
				case "/v1/secret/data/private/path-destination":
					destinationWrites.Add(1)
					want := map[string]any{"data": values, "options": map[string]any{"cas": json.Number("0")}}
					if !reflect.DeepEqual(kvWriteBody(t, r), want) {
						t.Error("partial move changed the copied snapshot or create-only CAS")
					}
					if sourceDeletes.Load() != 0 {
						t.Error("move deleted its source before confirming the copy")
					}
					destinationApplied.Store(true)
					kvReply(w, map[string]any{"version": 1})
				case "/v1/secret/delete/private/path-source":
					sourceDeletes.Add(1)
					if !destinationApplied.Load() || destinationWrites.Load() != 1 {
						t.Error("source deletion preceded the confirmed destination")
					}
					want := map[string]any{"versions": []any{json.Number("7")}}
					if !reflect.DeepEqual(kvWriteBody(t, r), want) {
						t.Error("move deleted a revision other than its captured source")
					}
					// Deletion can apply even when the caller never receives its result.
					sourceDeletionApplied.Store(true)
					if acknowledgement == "canceled" {
						cancel()
						<-r.Context().Done()
					} else {
						loseKVMutationResponse(t, w)
					}
				default:
					t.Error("partial move attempted discovery, a retry, or destination cleanup")
					w.WriteHeader(http.StatusNotFound)
				}
			})
			result, err := client.Move(ctx, "selected-token", "/secret/private/path-source", "/secret/private/path-destination", vault.WriteOptions{
				KVOptions: vault.KVOptions{Mount: "/secret", Version: 2},
			})
			assertKVSafeError(t, err)
			if !errors.Is(err, vault.ErrPartial) {
				t.Error("confirmed copy with unconfirmed source deletion did not report a partial move")
			}
			if !strings.Contains(err.Error(), "destination written") || !strings.Contains(err.Error(), "source deletion not confirmed") || !strings.Contains(err.Error(), "verify") {
				t.Error("partial move did not explain that both paths require verification")
			}
			if acknowledgement == "canceled" && !errors.Is(err, context.Canceled) {
				t.Error("partial move lost its source deletion cancellation")
			}
			want := vault.CopyResult{
				Source: "/secret/private/path-source", Destination: "/secret/private/path-destination",
				KVVersion: 2, Version: 1, SourceVersion: 7, SourceDeleted: false,
			}
			if result != want {
				t.Error("partial move did not retain its confirmed copy and unconfirmed deletion result")
			}
			assertKVResultFields(t, result, "source", "destination", "kv_version", "version", "source_version", "source_deleted")
			if requests.Load() != 3 || sourceReads.Load() != 1 || destinationWrites.Load() != 1 || sourceDeletes.Load() != 1 || !destinationApplied.Load() || !sourceDeletionApplied.Load() {
				t.Error("partial move retried a mutation, lost the copied values, or rolled back its destination")
			}
		})
	}
}
