package lifecycle

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"sort"
	"strings"

	"github.com/ml0renz0/secretwright/internal/fileformat"
	"github.com/ml0renz0/secretwright/internal/managedstate"
	"github.com/ml0renz0/secretwright/internal/vault"
)

// safeError keeps classification without carrying diagnostics from a backend.
func safeError(err error) error {
	if err == nil { return nil }
	for _, known := range []error{ErrPartial, ErrUnconfirmed, ErrConflict, ErrIO, ErrInvalidLifecycle, vault.ErrAccessUnconfirmed, vault.ErrAccessPartial, vault.ErrPermissionDenied, vault.ErrUnauthenticated, vault.ErrNotFound, vault.ErrConflict, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) { return known }
	}
	return ErrInvalidLifecycle
}

func partialError(err error) error { return errors.Join(ErrPartial, safeError(err)) }

func reportFor(spec Spec, operation string, store Session) Report {
	r := Report{Name: spec.Name, Operation: operation, Status: "unchanged"}
	if store != nil { r.Phase = store.Snapshot().Phase }
	return r
}

func noRoot(policies []string) bool {
	if len(policies) > 128 { return false }
	for _, policy := range policies { if !lifecycleName.MatchString(policy) || strings.EqualFold(policy, "root") { return false } }
	return true
}

func validRole(spec Spec, role RoleInfo) bool {
	r := role.State.Role
	minimum, _ := lifecycleSeconds(spec.Policy.MinimumNewTTL)
	return role.State.Exists && lifecycleHash.MatchString(role.Identity) && role.RoleID != "" && role.State.AuthMountAccessor != "" && role.State.TokenType == "service" && role.State.TokenPeriodSeconds == 0 && r.BindSecretID && r.TokenNoDefaultPolicy && r.TokenNumUses == 0 && r.TokenTTLSeconds >= minimum && r.TokenTTLSeconds <= 86400 && r.TokenMaxTTLSeconds >= r.TokenTTLSeconds && r.TokenMaxTTLSeconds <= 86400 && r.SecretIDTTLSeconds > 0 && r.SecretIDTTLSeconds <= 86400 && r.SecretIDNumUses >= 1 && r.SecretIDNumUses <= 1000 && len(r.TokenPolicies) > 0 && noRoot(r.TokenPolicies)
}

type rotationProof struct {
	receipt Receipt
	role RoleInfo
	target managedstate.Target
	consumer PrivateFile
}

// preflight reads local and remote proofs. It never spends a consumer use,
// issues a credential, probes the old token, or changes a checkpoint.
func preflight(ctx context.Context, spec Spec, store Session, backend Backend) (rotationProof, error) {
	if err := ctx.Err(); err != nil { return rotationProof{}, err }
	if store == nil || backend == nil { return rotationProof{}, ErrInvalidLifecycle }
	if _, err := ValidateSpec(spec); err != nil { return rotationProof{}, err }
	r := store.Snapshot()
	if r.APIVersion != "" && (ValidateReceipt(r) != nil || r.Name != spec.Name || r.ConfigSHA256 != SpecHash(spec)) { return rotationProof{}, ErrConflict }
	consumer, err := store.Consumer()
	if err != nil { return rotationProof{}, safeError(err) }
	value, err := privateValue(consumer.Data, true)
	if err != nil || value.Digest != consumer.Digest || value.Token != consumer.Token || backend.IsOperator(consumer.Token) { return rotationProof{}, ErrConflict }
	target, err := backend.Target(ctx)
	if err != nil { return rotationProof{}, safeError(err) }
	if managedstate.Validate(managedstate.State{APIVersion: managedstate.APIVersion, Blueprint: spec.Name, Target: target, Revision: 1, Resources: []managedstate.Record{}}) != nil { return rotationProof{}, ErrConflict }
	role, err := backend.Role(ctx, spec)
	if err != nil { return rotationProof{}, safeError(err) }
	if !validRole(spec, role) { return rotationProof{}, ErrConflict }
	if r.APIVersion != "" {
		if r.Target != target || r.RoleIdentity != role.Identity { return rotationProof{}, ErrConflict }
		expected := r.OldDigest
		switch r.Phase {
		case "published", "pending_retire", "retired": expected = r.NewDigest
		case "pending_publish":
			if consumer.Digest == r.NewDigest { expected = r.NewDigest }
		}
		if consumer.Digest != expected { return rotationProof{}, ErrConflict }
	}
	return rotationProof{receipt: r, role: role, target: target, consumer: consumer}, nil
}

func eligibleToken(spec Spec, info vault.TokenLifecycleInfo, entity string) bool {
	return info.Exists && info.Type == "service" && info.TTLSeconds > 0 && info.NumUses == 0 && noRoot(info.Policies) && noRoot(info.IdentityPolicies) && info.Path == "auth/"+spec.Provider.AuthMount+"/login" && info.RoleName == spec.Provider.Role && lifecycleUUID.MatchString(info.EntityID) && (entity == "" || info.EntityID == entity)
}

func tokenProof(ctx context.Context, spec Spec, backend Backend, token, entity string) (vault.TokenLifecycleInfo, error) {
	if token == "" || backend.IsOperator(token) { return vault.TokenLifecycleInfo{}, ErrConflict }
	info, err := backend.Token(ctx, token)
	if err != nil { return vault.TokenLifecycleInfo{}, safeError(err) }
	if !eligibleToken(spec, info, entity) { return vault.TokenLifecycleInfo{}, ErrConflict }
	return info, nil
}

func loadProof(store Session, kind, digest string) (PrivateFile, error) {
	file, err := store.Load(kind)
	if err != nil { return PrivateFile{}, safeError(err) }
	if digest == "" || file.Digest != digest || digestBytes(file.Data) != digest { return PrivateFile{}, ErrConflict }
	return file, nil
}

func candidate(ctx context.Context, spec Spec, store Session, backend Backend, role RoleInfo, minimum bool) (PrivateFile, vault.TokenLifecycleInfo, error) {
	r := store.Snapshot()
	file, err := loadProof(store, "new", r.NewDigest)
	if err != nil || file.Digest == r.OldDigest { return PrivateFile{}, vault.TokenLifecycleInfo{}, ErrConflict }
	info, err := tokenProof(ctx, spec, backend, file.Token, r.EntityID)
	if err != nil { return PrivateFile{}, vault.TokenLifecycleInfo{}, err }
	policies, expected := append([]string{}, info.Policies...), append([]string{}, role.State.Role.TokenPolicies...)
	sort.Strings(policies); sort.Strings(expected)
	if !reflect.DeepEqual(policies, expected) { return PrivateFile{}, vault.TokenLifecycleInfo{}, ErrConflict }
	threshold, _ := lifecycleSeconds(spec.Policy.MinimumNewTTL)
	if minimum && info.TTLSeconds < threshold { return PrivateFile{}, vault.TokenLifecycleInfo{}, ErrConflict }
	if err := backend.Probe(ctx, spec, file.Token); err != nil { return PrivateFile{}, vault.TokenLifecycleInfo{}, safeError(err) }
	return file, info, nil
}

func savePhase(store Session, phase string) error {
	r := store.Snapshot(); r.Revision++; r.Phase = phase
	return safeError(store.Save(r))
}

func Inspect(ctx context.Context, spec Spec, store Session, backend Backend) (Report, error) {
	r, err := Rotate(ctx, spec, store, backend, true)
	r.Operation = "inspect"
	return r, err
}

func Rotate(ctx context.Context, spec Spec, store Session, backend Backend, dryRun bool) (Report, error) {
	report := reportFor(spec, "rotate", store)
	proof, err := preflight(ctx, spec, store, backend)
	if err != nil { return report, err }
	r := proof.receipt
	if r.Phase == "published" || r.Phase == "pending_retire" {
		if r.Phase == "pending_retire" { return report, ErrPartial }
		info, err := tokenProof(ctx, spec, backend, proof.consumer.Token, r.EntityID)
		if err != nil { return report, err }
		report.TTLSeconds, report.Renewable, report.Status = info.TTLSeconds, info.Renewable, "awaiting_consumer_ack"
		return report, nil
	}
	switch r.Phase { case "prepared", "pending_login", "pending_publish": return report, ErrPartial }
	initial := r.APIVersion == "" || r.Phase == "retired" || r.Phase == "aborted"
	if initial {
		info, err := tokenProof(ctx, spec, backend, proof.consumer.Token, "")
		if err != nil { return report, err }
		below, _ := lifecycleSeconds(spec.Policy.RotateBelow)
		report.TTLSeconds, report.Renewable, report.Due = info.TTLSeconds, info.Renewable, info.TTLSeconds < below
		if !report.Due { report.Status = "not_due"; return report, nil }
		if dryRun { report.Status = "would_rotate"; return report, nil }
		if err := ctx.Err(); err != nil { return report, err }
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil { return report, ErrIO }
		format := r.Format; if format == "" { format = fileformat.YAML }
		r = Receipt{APIVersion: ReceiptVersion, Name: spec.Name, ConfigSHA256: SpecHash(spec), Target: proof.target, Revision: r.Revision+1, Generation: hex.EncodeToString(nonce), Phase: "prepared", RoleIdentity: proof.role.Identity, OldDigest: proof.consumer.Digest, EntityID: info.EntityID, Format: format}
		if err := store.Prepare(r, proof.consumer); err != nil { return reportFor(spec, "rotate", store), safeError(err) }
		if _, err := preflight(ctx, spec, store, backend); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
		credentials, err := backend.Issue(ctx, spec)
		if err != nil { return reportFor(spec, "rotate", store), partialError(err) }
		if credentials.RoleID != proof.role.RoleID { return reportFor(spec, "rotate", store), ErrPartial }
		var bundle bytes.Buffer
		if err := vault.EncodeAppRoleCredentials(&bundle, credentials); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
		if err := store.Put("bundle", bundle.Bytes()); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
		r = store.Snapshot(); r.BundleDigest = digestBytes(bundle.Bytes()); r.Phase = "secret_issued"; r.Revision++
		if err := store.Save(r); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
	} else {
		if dryRun { report.Status, report.Due = "would_rotate", true; return report, nil }
		if _, err := tokenProof(ctx, spec, backend, proof.consumer.Token, r.EntityID); err != nil { return report, err }
	}
	if store.Snapshot().Phase == "secret_issued" {
		r = store.Snapshot()
		file, err := loadProof(store, "bundle", r.BundleDigest)
		if err != nil { return reportFor(spec, "rotate", store), partialError(err) }
		credentials, err := vault.DecodeAppRoleCredentials(bytes.NewReader(file.Data))
		if err != nil || credentials.RoleID != proof.role.RoleID { return reportFor(spec, "rotate", store), ErrPartial }
		if _, err := preflight(ctx, spec, store, backend); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
		if err := savePhase(store, "pending_login"); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
		issued, err := backend.Login(ctx, spec, credentials)
		if err != nil { return reportFor(spec, "rotate", store), partialError(err) }
		newFile, err := privateValue([]byte(issued.Token+"\n"), true)
		if err != nil || newFile.Digest == r.OldDigest || backend.IsOperator(newFile.Token) { return reportFor(spec, "rotate", store), ErrPartial }
		if err := store.Put("new", newFile.Data); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
		r = store.Snapshot(); r.NewDigest = newFile.Digest; r.Phase = "candidate_ready"; r.Revision++
		if err := store.Save(r); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
	}
	proof, err = preflight(ctx, spec, store, backend)
	if err != nil { return reportFor(spec, "rotate", store), partialError(err) }
	if _, _, err := candidate(ctx, spec, store, backend, proof.role, true); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
	if store.Snapshot().Phase == "candidate_ready" { if err := savePhase(store, "verified"); err != nil { return reportFor(spec, "rotate", store), partialError(err) } }
	if store.Snapshot().Phase != "verified" { return reportFor(spec, "rotate", store), ErrConflict }
	if err := savePhase(store, "pending_publish"); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
	if err := store.Publish(store.Snapshot().OldDigest); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
	consumer, err := store.Consumer()
	if err != nil || consumer.Digest != store.Snapshot().NewDigest { return reportFor(spec, "rotate", store), ErrPartial }
	if err := backend.Probe(ctx, spec, consumer.Token); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
	if err := savePhase(store, "published"); err != nil { return reportFor(spec, "rotate", store), partialError(err) }
	report = reportFor(spec, "rotate", store); report.Status, report.Due = "awaiting_consumer_ack", true
	return report, nil
}

func Retire(ctx context.Context, spec Spec, store Session, backend Backend, ack bool) (Report, error) {
	report := reportFor(spec, "retire", store)
	if !ack { return report, ErrInvalidLifecycle }
	proof, err := preflight(ctx, spec, store, backend)
	if err != nil { return report, err }
	if proof.receipt.Phase == "retired" { report.Status = "retired"; return report, nil }
	if proof.receipt.Phase != "published" { return report, ErrConflict }
	_, info, err := candidate(ctx, spec, store, backend, proof.role, false)
	if err != nil { return report, err }
	old, err := loadProof(store, "old", proof.receipt.OldDigest)
	if err != nil || backend.IsOperator(old.Token) { return report, ErrConflict }
	oldInfo, err := backend.Token(ctx, old.Token)
	if err != nil { return report, safeError(err) }
	if oldInfo.Exists && !eligibleToken(spec, oldInfo, proof.receipt.EntityID) { return report, ErrConflict }
	if err := ctx.Err(); err != nil { return report, err }
	if err := savePhase(store, "pending_retire"); err != nil { return reportFor(spec, "retire", store), partialError(err) }
	if oldInfo.Exists {
		if err := backend.Revoke(ctx, old.Token); err != nil {
			if errors.Is(err, vault.ErrPermissionDenied) || errors.Is(err, vault.ErrUnauthenticated) {
				if savePhase(store, "published") == nil { return reportFor(spec, "retire", store), safeError(err) }
			}
			return reportFor(spec, "retire", store), partialError(err)
		}
	}
	oldInfo, err = backend.Token(ctx, old.Token)
	if err != nil || oldInfo.Exists { return reportFor(spec, "retire", store), partialError(err) }
	if err := savePhase(store, "retired"); err != nil { return reportFor(spec, "retire", store), partialError(err) }
	report = reportFor(spec, "retire", store); report.Status, report.TTLSeconds, report.Renewable = "retired", info.TTLSeconds, info.Renewable
	return report, nil
}
