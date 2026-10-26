package lifecycle_test

import (
	"context"
	"testing"

	"github.com/ml0renz0/secretwright/internal/lifecycle"
	"github.com/ml0renz0/secretwright/internal/vault"
)

// The hooks model another writer changing a local or remote proof during a
// successful read. A successful probe cannot authorize a later destructive
// action against a proof that has already changed.
type lateProofBackend struct {
	*rotationBackend
	afterProbe func()
	afterToken func(string)
}

func (backend *lateProofBackend) Probe(ctx context.Context, spec lifecycle.Spec, token string) error {
	err := backend.rotationBackend.Probe(ctx, spec, token)
	if err == nil && backend.afterProbe != nil {
		backend.afterProbe()
	}
	return err
}

func (backend *lateProofBackend) Token(ctx context.Context, token string) (vault.TokenLifecycleInfo, error) {
	info, err := backend.rotationBackend.Token(ctx, token)
	if err == nil && backend.afterToken != nil {
		backend.afterToken(token)
	}
	return info, err
}

func TestRetirementRechecksConsumerAndRoleAfterProbeAndOldLookup(t *testing.T) {
	for _, change := range []string{"consumer-after-probe", "role-after-probe", "role-config-after-probe", "consumer-after-old-lookup", "role-after-old-lookup", "role-config-after-old-lookup"} {
		t.Run(change, func(t *testing.T) {
			events := []string{}
			store := newRotationSession(t, &events)
			backend := &lateProofBackend{rotationBackend: newRotationBackend(&events)}
			spec := lifecycleSpec(t)
			if _, err := lifecycle.Rotate(context.Background(), spec, store, backend, false); err != nil {
				t.Fatal("could not prepare published generation")
			}
			mutate := func() {
				if change == "consumer-after-probe" || change == "consumer-after-old-lookup" {
					store.consumer = rotationPrivate("private-foreign-token\n")
				} else if change == "role-config-after-probe" || change == "role-config-after-old-lookup" {
					backend.role.State.Role.TokenPolicies = []string{"changed-policy"}
				} else {
					backend.role.Identity = rotationHash("replaced-role-after-read")
				}
			}
			if change == "consumer-after-probe" || change == "role-after-probe" || change == "role-config-after-probe" {
				backend.afterProbe = mutate
			} else {
				backend.afterToken = func(token string) {
					if token == "private-old-token" {
						mutate()
					}
				}
			}
			report, err := lifecycle.Retire(context.Background(), spec, store, backend, true)
			if err == nil || backend.revokes != 0 || !backend.tokens["private-old-token"].Exists || !backend.tokens["private-new-token"].Exists {
				t.Error("retirement revoked a working credential after its consumer or role proof changed during verification")
			}
			privateRotationReport(t, report, err)
		})
	}
}

func TestRotationRechecksRoleAndConsumerAfterCandidateProbeBeforePublishing(t *testing.T) {
	for _, change := range []string{"consumer", "role", "role-config"} {
		t.Run(change, func(t *testing.T) {
			events := []string{}
			store := newRotationSession(t, &events)
			backend := &lateProofBackend{rotationBackend: newRotationBackend(&events)}
			backend.afterProbe = func() {
				if change == "consumer" {
					store.consumer = rotationPrivate("private-foreign-token\n")
				} else if change == "role-config" {
					backend.role.State.Role.TokenPolicies = []string{"changed-policy"}
				} else {
					backend.role.Identity = rotationHash("replaced-role-after-probe")
				}
			}
			report, err := lifecycle.Rotate(context.Background(), lifecycleSpec(t), store, backend, false)
			if err == nil || store.published != 0 || backend.revokes != 0 || !backend.tokens["private-old-token"].Exists {
				t.Error("rotation published after its consumer or role proof changed during candidate verification")
			}
			privateRotationReport(t, report, err)
		})
	}
}

type lateProofSession struct {
	*rotationSession
	newLoadError error
}

func (store *lateProofSession) Load(kind string) (lifecycle.PrivateFile, error) {
	if kind == "new" && store.newLoadError != nil {
		return lifecycle.PrivateFile{}, store.newLoadError
	}
	return store.rotationSession.Load(kind)
}

func TestRecoveryCannotAbandonAnUnreadableCandidateArtifact(t *testing.T) {
	events := []string{}
	original := newRotationSession(t, &events)
	backend := newRotationBackend(&events)
	backend.loginErr = vault.ErrAccessUnconfirmed
	spec := lifecycleSpec(t)
	if _, err := lifecycle.Rotate(context.Background(), spec, original, backend, false); err == nil || original.receipt.Phase != "pending_login" || original.receipt.NewDigest != "" {
		t.Fatal("could not prepare uncertain login checkpoint")
	}
	store := &lateProofSession{rotationSession: original, newLoadError: lifecycle.ErrIO}
	saved, issued, logins := original.saves, backend.issues, backend.logins
	report, err := lifecycle.Recover(context.Background(), spec, store, backend, true)
	if err == nil || original.receipt.Phase != "pending_login" || original.saves != saved || backend.issues != issued || backend.logins != logins || backend.revokes != 0 {
		t.Error("recovery treated an unreadable candidate as proof that no live candidate exists")
	}
	privateRotationReport(t, report, err)
}

func TestRecoveryDoesNotConfirmPendingLoginWithForeignTokenPolicies(t *testing.T) {
	events := []string{}
	store := newRotationSession(t, &events)
	backend := newRotationBackend(&events)
	backend.loginErr = vault.ErrAccessUnconfirmed
	spec := lifecycleSpec(t)
	if _, err := lifecycle.Rotate(context.Background(), spec, store, backend, false); err == nil || store.receipt.Phase != "pending_login" {
		t.Fatal("could not prepare uncertain login checkpoint")
	}
	store.files["new"] = rotationPrivate("private-new-token\n")
	info := backend.tokens["private-new-token"]
	info.Policies = []string{"foreign"}
	backend.tokens["private-new-token"] = info
	saved, issued, logins := store.saves, backend.issues, backend.logins
	report, err := lifecycle.Recover(context.Background(), spec, store, backend, false)
	if err == nil || store.receipt.Phase != "pending_login" || store.saves != saved || backend.issues != issued || backend.logins != logins || backend.revokes != 0 {
		t.Error("recovery confirmed a login artifact whose token policies do not match the current AppRole")
	}
	privateRotationReport(t, report, err)
}
