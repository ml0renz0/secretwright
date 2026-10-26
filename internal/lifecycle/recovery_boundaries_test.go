package lifecycle_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/ml0renz0/secretwright/internal/fileformat"
	"github.com/ml0renz0/secretwright/internal/lifecycle"
	"github.com/ml0renz0/secretwright/internal/vault"
)

func TestRecoveryRecognizesDurableCredentialsWithoutRepeatingTheirIssuance(t *testing.T) {
	for _, interrupted := range []struct{ checkpoint, recovered string }{{"secret_issued", "secret_issued"}, {"candidate_ready", "candidate_ready"}} {
		t.Run(interrupted.checkpoint, func(t *testing.T) {
			events := []string{}
			store, backend := newRotationSession(t, &events), newRotationBackend(&events)
			spec := lifecycleSpec(t)
			store.failSave = func(r lifecycle.Receipt) error { if r.Phase == interrupted.checkpoint { return lifecycle.ErrUnconfirmed }; return nil }
			if _, err := lifecycle.Rotate(context.Background(), spec, store, backend, false); !errors.Is(err, lifecycle.ErrPartial) { t.Fatal("checkpoint interruption was not reported as partial") }
			issues, logins := backend.issues, backend.logins
			store.failSave = nil
			if _, err := lifecycle.Recover(context.Background(), spec, store, backend, false); err != nil || store.receipt.Phase != interrupted.recovered || backend.issues != issues || backend.logins != logins || store.published != 0 || backend.revokes != 0 { t.Fatal("recovery replayed an RPC instead of recognizing the durable artifact") }
			if _, err := lifecycle.Rotate(context.Background(), spec, store, backend, false); err != nil || store.receipt.Phase != "published" || backend.issues != 1 || backend.logins != 1 { t.Error("rotation could not resume the next known step after observation") }
		})
	}
}

func TestRecoveryOfUnpublishedConsumerDoesNotPublishIt(t *testing.T) {
	events := []string{}
	store, backend := newRotationSession(t, &events), newRotationBackend(&events)
	spec := lifecycleSpec(t)
	backend.probeErr = vault.ErrPermissionDenied
	if _, err := lifecycle.Rotate(context.Background(), spec, store, backend, false); !errors.Is(err, lifecycle.ErrPartial) { t.Fatal("could not prepare unpublished candidate") }
	backend.probeErr = nil
	store.receipt.Phase = "pending_publish"
	if _, err := lifecycle.Recover(context.Background(), spec, store, backend, false); err != nil || store.receipt.Phase != "verified" || store.consumer.Token != "private-old-token" || store.published != 0 || backend.revokes != 0 { t.Error("read-only recovery published or revoked a credential") }
}

func TestRetirementFailureRequiresANewExplicitAcknowledgement(t *testing.T) {
	for _, failure := range []error{vault.ErrPermissionDenied, vault.ErrAccessUnconfirmed} {
		events := []string{}
		store, backend := newRotationSession(t, &events), newRotationBackend(&events)
		spec := lifecycleSpec(t)
		if _, err := lifecycle.Rotate(context.Background(), spec, store, backend, false); err != nil { t.Fatal("could not publish fixture") }
		backend.revokeErr = failure
		_, err := lifecycle.Retire(context.Background(), spec, store, backend, true)
		if errors.Is(failure, vault.ErrPermissionDenied) {
			if !errors.Is(err, vault.ErrPermissionDenied) || errors.Is(err, lifecycle.ErrPartial) || store.receipt.Phase != "published" { t.Error("definite denial did not restore the published checkpoint") }
		} else {
			if !errors.Is(err, lifecycle.ErrPartial) || store.receipt.Phase != "pending_retire" { t.Fatal("uncertain retirement lost its checkpoint") }
			if _, err := lifecycle.Recover(context.Background(), spec, store, backend, false); err != nil || store.receipt.Phase != "published" || backend.revokes != 1 { t.Error("observing a live old token replayed revocation") }
		}
		backend.revokeErr = nil
		if _, err := lifecycle.Retire(context.Background(), spec, store, backend, false); err == nil || backend.revokes != 1 { t.Error("retry retired without a new consumer acknowledgement") }
		if _, err := lifecycle.Retire(context.Background(), spec, store, backend, true); err != nil || store.receipt.Phase != "retired" || backend.revokes != 2 { t.Error("explicit acknowledged retirement could not retry after observation") }
	}
}

func TestReceiptEncodingMustMatchItsDeclaredFormat(t *testing.T) {
	for _, actual := range []fileformat.Format{fileformat.YAML, fileformat.JSON} {
		spec, path := ioFixture(t)
		store := ioOpen(t, spec, path, actual, true)
		receipt := ioPrepare(t, store, spec, actual)
		if store.Close() != nil { t.Fatal("could not close fixture") }
		if actual == fileformat.YAML { receipt.Format = fileformat.JSON } else { receipt.Format = fileformat.YAML }
		raw, err := json.Marshal(receipt)
		if err != nil { t.Fatal("could not encode fixture") }
		body, err := fileformat.EncodeJSON(raw, actual)
		if err != nil { t.Fatal("could not render fixture") }
		if os.WriteFile(path, body, 0o600) != nil { t.Fatal("could not replace fixture encoding") }
		if opened, err := lifecycle.Open(spec, path, "", true); err == nil || opened != nil { if opened != nil { _ = opened.Close() }; t.Error("receipt silently changed its physical encoding on reopen") }
		ioNoArtifact(t, path+".lock")
	}
}
