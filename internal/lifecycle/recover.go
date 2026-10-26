package lifecycle

import (
	"bytes"
	"context"

	"github.com/ml0renz0/secretwright/internal/vault"
)

// Recover only observes Vault. It can advance local evidence but never repeats
// an issuance, login, publication or revocation after an uncertain response.
func Recover(ctx context.Context, spec Spec, store Session, backend Backend, abandon bool) (Report, error) {
	report := reportFor(spec, "recover", store)
	proof, err := preflight(ctx, spec, store, backend)
	if err != nil { return report, err }
	r := proof.receipt
	if r.APIVersion == "" { return report, ErrConflict }
	if r.Phase == "retired" || r.Phase == "aborted" { return report, nil }
	if abandon {
		if r.Phase == "published" || r.Phase == "pending_retire" || proof.consumer.Digest != r.OldDigest { return report, ErrConflict }
		if known, err := store.Load("new"); err == nil {
			if r.NewDigest != "" && known.Digest != r.NewDigest || backend.IsOperator(known.Token) { return report, ErrConflict }
			info, err := backend.Token(ctx, known.Token)
			if err != nil { return report, safeError(err) }
			if info.Exists { return report, ErrConflict }
		} else if r.NewDigest != "" { return report, ErrConflict }
		if err := savePhase(store, "aborted"); err != nil { return reportFor(spec, "recover", store), partialError(err) }
		report = reportFor(spec, "recover", store); report.Status = "aborted"
		return report, nil
	}
	phase := ""
	switch r.Phase {
	case "prepared":
		bundle, err := store.Load("bundle")
		if err != nil { return report, ErrPartial }
		credentials, err := vault.DecodeAppRoleCredentials(bytes.NewReader(bundle.Data))
		if err != nil || credentials.RoleID != proof.role.RoleID || digestBytes(bundle.Data) != bundle.Digest { return report, ErrConflict }
		r.BundleDigest, r.Phase, r.Revision = bundle.Digest, "secret_issued", r.Revision+1
		if err := store.Save(r); err != nil { return reportFor(spec, "recover", store), partialError(err) }
	case "pending_login":
		known, err := store.Load("new")
		if err != nil || known.Digest == r.OldDigest || digestBytes(known.Data) != known.Digest { return report, ErrPartial }
		info, err := tokenProof(ctx, spec, backend, known.Token, r.EntityID)
		minimum, _ := lifecycleSeconds(spec.Policy.MinimumNewTTL)
		if err != nil || info.TTLSeconds < minimum { return report, ErrPartial }
		if err := backend.Probe(ctx, spec, known.Token); err != nil { return report, partialError(err) }
		r.NewDigest, r.Phase, r.Revision = known.Digest, "candidate_ready", r.Revision+1
		if err := store.Save(r); err != nil { return reportFor(spec, "recover", store), partialError(err) }
	case "pending_publish":
		if _, _, err := candidate(ctx, spec, store, backend, proof.role, false); err != nil { return report, partialError(err) }
		phase = "verified"
		if proof.consumer.Digest == r.NewDigest { phase = "published" }
	case "pending_retire":
		if _, _, err := candidate(ctx, spec, store, backend, proof.role, false); err != nil { return report, partialError(err) }
		old, err := loadProof(store, "old", r.OldDigest)
		if err != nil || backend.IsOperator(old.Token) { return report, ErrConflict }
		info, err := backend.Token(ctx, old.Token)
		if err != nil { return report, safeError(err) }
		phase = "retired"
		if info.Exists { if !eligibleToken(spec, info, r.EntityID) { return report, ErrConflict }; phase = "published" }
	case "candidate_ready", "verified":
		if _, _, err := candidate(ctx, spec, store, backend, proof.role, false); err != nil { return report, partialError(err) }
	case "secret_issued", "published":
	default: return report, ErrConflict
	}
	if phase != "" { if err := savePhase(store, phase); err != nil { return reportFor(spec, "recover", store), partialError(err) } }
	report = reportFor(spec, "recover", store); report.Status = "recovered"
	return report, nil
}
