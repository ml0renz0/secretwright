package lifecycle_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/fileformat"
	"github.com/ml0renz0/secretwright/internal/lifecycle"
	"github.com/ml0renz0/secretwright/internal/managedstate"
	"github.com/ml0renz0/secretwright/internal/vault"
)

const rotationEntity = "11111111-1111-4111-8111-111111111111"

func rotationHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func rotationPrivate(value string) lifecycle.PrivateFile {
	body := []byte(value)
	return lifecycle.PrivateFile{Data: body, Token: strings.TrimSpace(value), Digest: rotationHash(value)}
}

func rotationTarget() managedstate.Target {
	return managedstate.Target{AddressSHA256: rotationHash("fixture-address"), ClusterID: "22222222-2222-4222-8222-222222222222"}
}

func rotationReceipt(spec lifecycle.Spec, phase string) lifecycle.Receipt {
	receipt := lifecycle.Receipt{
		APIVersion: "secretwright/rotation/v1", Name: spec.Name, ConfigSHA256: lifecycle.SpecHash(spec), Target: rotationTarget(),
		Revision: 1, Generation: strings.Repeat("a", 32), Phase: phase, RoleIdentity: rotationHash("role-identity"),
		OldDigest: rotationHash("private-old-token\n"), EntityID: rotationEntity, Format: fileformat.YAML,
	}
	if phase != "prepared" && phase != "aborted" {
		receipt.BundleDigest = rotationHash("fixture-bundle")
	}
	if phase != "prepared" && phase != "secret_issued" && phase != "pending_login" && phase != "aborted" {
		receipt.NewDigest = rotationHash("private-new-token\n")
	}
	return receipt
}

type rotationSession struct {
	t        *testing.T
	receipt  lifecycle.Receipt
	consumer lifecycle.PrivateFile
	files    map[string]lifecycle.PrivateFile
	events   *[]string
	saves    int
	prepared int
	published int
	failSave func(lifecycle.Receipt) error
}

func newRotationSession(t *testing.T, events *[]string) *rotationSession {
	return &rotationSession{t: t, receipt: lifecycle.Receipt{Format: fileformat.YAML}, consumer: rotationPrivate("private-old-token\n"), files: make(map[string]lifecycle.PrivateFile), events: events}
}

func (store *rotationSession) Snapshot() lifecycle.Receipt { return store.receipt }
func (store *rotationSession) Consumer() (lifecycle.PrivateFile, error) { return store.consumer, nil }
func (store *rotationSession) Prepare(receipt lifecycle.Receipt, old lifecycle.PrivateFile) error {
	store.t.Helper()
	if lifecycle.ValidateReceipt(receipt) != nil || receipt.Phase != "prepared" || receipt.OldDigest != old.Digest || receipt.Revision != store.receipt.Revision+1 {
		store.t.Fatal("rotation prepared an invalid initial checkpoint")
	}
	store.prepared++
	*store.events = append(*store.events, "prepare")
	store.receipt, store.files["old"] = receipt, old
	return nil
}
func (store *rotationSession) Save(receipt lifecycle.Receipt) error {
	store.t.Helper()
	if lifecycle.ValidateReceipt(receipt) != nil || receipt.Revision != store.receipt.Revision+1 || receipt.Name != store.receipt.Name || receipt.ConfigSHA256 != store.receipt.ConfigSHA256 || receipt.Target != store.receipt.Target {
		store.t.Fatal("rotation attempted an invalid or unbound checkpoint")
	}
	*store.events = append(*store.events, "save:"+receipt.Phase)
	if store.failSave != nil {
		if err := store.failSave(receipt); err != nil {
			return err
		}
	}
	store.saves++
	store.receipt = receipt
	return nil
}
func (store *rotationSession) Put(kind string, body []byte) error {
	if _, exists := store.files[kind]; exists || kind != "new" && kind != "bundle" {
		return lifecycle.ErrConflict
	}
	*store.events = append(*store.events, "put:"+kind)
	value := rotationPrivate(string(body))
	if kind == "bundle" {
		value.Token = ""
	}
	store.files[kind] = value
	return nil
}
func (store *rotationSession) Load(kind string) (lifecycle.PrivateFile, error) {
	value, found := store.files[kind]
	if !found {
		return lifecycle.PrivateFile{}, lifecycle.ErrIO
	}
	return value, nil
}
func (store *rotationSession) Publish(expected string) error {
	if expected != store.consumer.Digest || store.files["new"].Digest != store.receipt.NewDigest || store.receipt.Phase != "pending_publish" {
		return lifecycle.ErrConflict
	}
	*store.events = append(*store.events, "publish")
	store.published++
	store.consumer = store.files["new"]
	return nil
}

type rotationBackend struct {
	events *[]string
	role lifecycle.RoleInfo
	target managedstate.Target
	tokens map[string]vault.TokenLifecycleInfo
	issueErr, loginErr, probeErr, revokeErr error
	issues, logins, probes, revokes int
}

func newRotationBackend(events *[]string) *rotationBackend {
	info := vault.TokenLifecycleInfo{Exists: true, TTLSeconds: 60, Renewable: true, Type: "service", Policies: []string{"payments"}, IdentityPolicies: []string{}, Path: "auth/approle/login", RoleName: "payments-api", EntityID: rotationEntity}
	newInfo := info
	newInfo.TTLSeconds = 1200
	return &rotationBackend{events: events, target: rotationTarget(), role: lifecycle.RoleInfo{
		State: vault.BlueprintAppRoleState{Exists: true, AuthMountAccessor: "auth_fixture", TokenType: "service", Role: vault.RoleReport{
			Name: "payments-api", AuthMount: "approle", TokenPolicies: []string{"payments"}, TokenTTLSeconds: 1200, TokenMaxTTLSeconds: 3600, SecretIDTTLSeconds: 3600, SecretIDNumUses: 1, BindSecretID: true, TokenNoDefaultPolicy: true,
		}}, Identity: rotationHash("role-identity"), RoleID: "private-role-id",
	}, tokens: map[string]vault.TokenLifecycleInfo{"private-old-token": info, "private-new-token": newInfo}}
}
func (backend *rotationBackend) Target(context.Context) (managedstate.Target, error) { return backend.target, nil }
func (backend *rotationBackend) Role(context.Context, lifecycle.Spec) (lifecycle.RoleInfo, error) { return backend.role, nil }
func (backend *rotationBackend) Token(_ context.Context, token string) (vault.TokenLifecycleInfo, error) {
	*backend.events = append(*backend.events, "token:"+token)
	return backend.tokens[token], nil
}
func (backend *rotationBackend) IsOperator(token string) bool { return token == "private-operator-token" }
func (backend *rotationBackend) Issue(context.Context, lifecycle.Spec) (vault.AppRoleCredentials, error) {
	*backend.events = append(*backend.events, "issue")
	backend.issues++
	return vault.AppRoleCredentials{RoleID: "private-role-id", SecretID: "private-secret-id", SecretIDAccessor: "private-secret-accessor"}, backend.issueErr
}
func (backend *rotationBackend) Login(_ context.Context, _ lifecycle.Spec, credentials vault.AppRoleCredentials) (vault.IssuedToken, error) {
	*backend.events = append(*backend.events, "login")
	backend.logins++
	if credentials.RoleID != "private-role-id" || credentials.SecretID != "private-secret-id" {
		return vault.IssuedToken{}, lifecycle.ErrInvalidLifecycle
	}
	return vault.IssuedToken{Token: "private-new-token", Accessor: "private-new-accessor", Report: vault.CredentialReport{Kind: "approle_login", TTLSeconds: 1200, Renewable: true, Policies: []string{"payments"}, EntityID: rotationEntity}}, backend.loginErr
}
func (backend *rotationBackend) Probe(_ context.Context, _ lifecycle.Spec, token string) error {
	*backend.events = append(*backend.events, "probe:"+token)
	backend.probes++
	if token != "private-new-token" || !backend.tokens[token].Exists {
		return vault.ErrPermissionDenied
	}
	return backend.probeErr
}
func (backend *rotationBackend) Revoke(_ context.Context, token string) error {
	*backend.events = append(*backend.events, "revoke:"+token)
	backend.revokes++
	if token != "private-old-token" {
		return lifecycle.ErrConflict
	}
	if backend.revokeErr == nil {
		delete(backend.tokens, token)
	}
	return backend.revokeErr
}

func privateRotationReport(t *testing.T, report lifecycle.Report, err error) {
	t.Helper()
	body, encodeErr := json.Marshal(report)
	if encodeErr != nil {
		t.Fatal("could not encode lifecycle metadata")
	}
	for _, marker := range []string{"private-", "secret_id", "token_file", "old_digest", "config_sha256", "/run/payments", rotationHash("role-identity")} {
		if strings.Contains(string(body), marker) || err != nil && strings.Contains(err.Error(), marker) {
			t.Error("lifecycle metadata or error exposed private configuration or credentials")
		}
	}
}

func eventIndex(events []string, wanted string) int {
	for index, value := range events {
		if value == wanted { return index }
	}
	return -1
}

func TestRotationPublishesVerifiedCredentialAndKeepsOldUntilExplicitAck(t *testing.T) {
	spec := lifecycleSpec(t)
	events := []string{}
	store, backend := newRotationSession(t, &events), newRotationBackend(&events)
	report, err := lifecycle.Rotate(context.Background(), spec, store, backend, false)
	if err != nil || report.Status != "awaiting_consumer_ack" || store.receipt.Phase != "published" || store.consumer.Token != "private-new-token" || backend.issues != 1 || backend.logins != 1 || backend.revokes != 0 || !backend.tokens["private-old-token"].Exists {
		t.Fatal("rotation failed to publish the usable candidate while preserving the old credential")
	}
	if eventIndex(events, "prepare") >= eventIndex(events, "issue") || eventIndex(events, "save:pending_login") >= eventIndex(events, "login") || eventIndex(events, "probe:private-new-token") >= eventIndex(events, "publish") || eventIndex(events, "save:pending_publish") >= eventIndex(events, "publish") {
		t.Error("rotation sent a mutation without its write-ahead evidence or published before verification")
	}
	privateRotationReport(t, report, err)
	saves := store.saves
	if report, err := lifecycle.Rotate(context.Background(), spec, store, backend, false); err != nil || report.Status != "awaiting_consumer_ack" || store.saves != saves || backend.issues != 1 || backend.logins != 1 || backend.revokes != 0 {
		t.Error("a repeated cron invocation minted or retired another credential while awaiting consumer acknowledgement")
	}
	if _, err := lifecycle.Retire(context.Background(), spec, store, backend, false); err == nil || backend.revokes != 0 {
		t.Error("retirement proceeded without an explicit consumer acknowledgement")
	}
	report, err = lifecycle.Retire(context.Background(), spec, store, backend, true)
	if err != nil || store.receipt.Phase != "retired" || backend.revokes != 1 || backend.tokens["private-old-token"].Exists || !backend.tokens["private-new-token"].Exists || store.consumer.Token != "private-new-token" {
		t.Fatal("acknowledged retirement did not revoke only the old credential")
	}
	if eventIndex(events, "save:pending_retire") >= eventIndex(events, "revoke:private-old-token") {
		t.Error("old credential retirement did not have a pending checkpoint")
	}
	privateRotationReport(t, report, err)
}

func TestLifecycleDryRunAndTTLThresholdMakeNoArtifactsOrMutations(t *testing.T) {
	for _, due := range []bool{false, true} {
		for _, dry := range []bool{false, true} {
			if due && !dry { continue }
			events := []string{}
			store, backend := newRotationSession(t, &events), newRotationBackend(&events)
			if !due {
				info := backend.tokens["private-old-token"]
				info.TTLSeconds = 1200
				backend.tokens["private-old-token"] = info
			}
			report, err := lifecycle.Rotate(context.Background(), lifecycleSpec(t), store, backend, dry)
			if err != nil || report.Due != due || store.prepared != 0 || store.saves != 0 || len(store.files) != 0 || backend.issues != 0 || backend.logins != 0 || backend.probes != 0 || backend.revokes != 0 {
				t.Error("a dry run or non-due rotation created artifacts, spent consumer uses, or mutated Vault")
			}
			privateRotationReport(t, report, err)
		}
	}
}

func TestLifecycleRejectsUnsafeOldCredentialsAndRoleBeforeIssuing(t *testing.T) {
	for _, change := range []string{"operator", "root", "uses", "expired", "foreign-role", "foreign-entity", "unbounded-role", "limited-role"} {
		t.Run(change, func(t *testing.T) {
			events := []string{}
			store, backend := newRotationSession(t, &events), newRotationBackend(&events)
			info := backend.tokens["private-old-token"]
			switch change {
			case "operator": store.consumer = rotationPrivate("private-operator-token\n")
			case "root": info.Policies = []string{"root"}
			case "uses": info.NumUses = 1
			case "expired": info.Exists = false
			case "foreign-role": info.RoleName = "another-role"
			case "foreign-entity": info.EntityID = ""
			case "unbounded-role": backend.role.State.Role.TokenTTLSeconds = 0
			case "limited-role": backend.role.State.Role.TokenNumUses = 1
			}
			backend.tokens["private-old-token"] = info
			report, err := lifecycle.Rotate(context.Background(), lifecycleSpec(t), store, backend, false)
			if err == nil || store.prepared != 0 || store.saves != 0 || backend.issues != 0 || backend.logins != 0 || store.published != 0 || backend.revokes != 0 {
				t.Error("unsafe old credential or role passed rotation preflight")
			}
			privateRotationReport(t, report, err)
		})
	}
}

func TestRotationVerificationFailureNeverReplacesOrRevokesOldCredential(t *testing.T) {
	for _, failure := range []string{"probe", "entity", "policies", "ttl"} {
		t.Run(failure, func(t *testing.T) {
			events := []string{}
			store, backend := newRotationSession(t, &events), newRotationBackend(&events)
			newInfo := backend.tokens["private-new-token"]
			switch failure {
			case "probe": backend.probeErr = errors.New("private-probe-body")
			case "entity": newInfo.EntityID = "33333333-3333-4333-8333-333333333333"
			case "policies": newInfo.Policies = []string{"foreign"}
			case "ttl": newInfo.TTLSeconds = 30
			}
			backend.tokens["private-new-token"] = newInfo
			report, err := lifecycle.Rotate(context.Background(), lifecycleSpec(t), store, backend, false)
			if !errors.Is(err, lifecycle.ErrPartial) || store.consumer.Token != "private-old-token" || store.published != 0 || backend.revokes != 0 || !backend.tokens["private-old-token"].Exists {
				t.Error("failed candidate verification replaced or revoked the working old credential")
			}
			privateRotationReport(t, report, err)
		})
	}
}

func TestUncertainIssuanceAndLoginAreNeverAutomaticallyReplayed(t *testing.T) {
	for _, failure := range []string{"issue", "login"} {
		t.Run(failure, func(t *testing.T) {
			events := []string{}
			store, backend := newRotationSession(t, &events), newRotationBackend(&events)
			if failure == "issue" { backend.issueErr = vault.ErrAccessUnconfirmed } else { backend.loginErr = vault.ErrAccessUnconfirmed }
			report, err := lifecycle.Rotate(context.Background(), lifecycleSpec(t), store, backend, false)
			if !errors.Is(err, lifecycle.ErrPartial) || store.consumer.Token != "private-old-token" || store.published != 0 || backend.revokes != 0 {
				t.Fatal("unknown issuance or login did not preserve the working consumer")
			}
			issues, logins := backend.issues, backend.logins
			if _, err := lifecycle.Rotate(context.Background(), lifecycleSpec(t), store, backend, false); err == nil || backend.issues != issues || backend.logins != logins {
				t.Error("pending rotation automatically replayed an uncertain RPC")
			}
			privateRotationReport(t, report, err)
		})
	}
}

func TestRotationBindingAndConsumerChangesStopRetirementBeforeRevocation(t *testing.T) {
	for _, change := range []string{"consumer", "role", "target", "probe"} {
		t.Run(change, func(t *testing.T) {
			events := []string{}
			store, backend := newRotationSession(t, &events), newRotationBackend(&events)
			spec := lifecycleSpec(t)
			if _, err := lifecycle.Rotate(context.Background(), spec, store, backend, false); err != nil { t.Fatal("could not prepare published generation") }
			switch change {
			case "consumer": store.consumer = rotationPrivate("private-foreign-token\n")
			case "role": backend.role.Identity = rotationHash("replaced-role")
			case "target": backend.target.AddressSHA256 = rotationHash("another-address")
			case "probe": backend.probeErr = vault.ErrPermissionDenied
			}
			report, err := lifecycle.Retire(context.Background(), spec, store, backend, true)
			if err == nil || backend.revokes != 0 || !backend.tokens["private-old-token"].Exists || !backend.tokens["private-new-token"].Exists {
				t.Error("retirement ignored a changed consumer, target, role or unusable new token")
			}
			privateRotationReport(t, report, err)
		})
	}
}

func TestRotationCheckpointFailureStopsBeforePublishingAndRecoveryNeverReplays(t *testing.T) {
	events := []string{}
	store, backend := newRotationSession(t, &events), newRotationBackend(&events)
	store.failSave = func(receipt lifecycle.Receipt) error {
		if receipt.Phase == "published" { return lifecycle.ErrUnconfirmed }
		return nil
	}
	spec := lifecycleSpec(t)
	report, err := lifecycle.Rotate(context.Background(), spec, store, backend, false)
	if !errors.Is(err, lifecycle.ErrPartial) || store.receipt.Phase != "pending_publish" || store.consumer.Token != "private-new-token" || backend.revokes != 0 {
		t.Fatal("publication checkpoint failure lost its pending evidence or revoked the old token")
	}
	privateRotationReport(t, report, err)
	store.failSave = nil
	issued, logins, revoked, published := backend.issues, backend.logins, backend.revokes, store.published
	report, err = lifecycle.Recover(context.Background(), spec, store, backend, false)
	if err != nil || store.receipt.Phase != "published" || backend.issues != issued || backend.logins != logins || backend.revokes != revoked || store.published != published {
		t.Error("recovery replayed an issuance, login, publication or revocation")
	}
	privateRotationReport(t, report, err)
}

func TestLifecycleCanceledBeforeStartingLeavesNoGeneration(t *testing.T) {
	events := []string{}
	store, backend := newRotationSession(t, &events), newRotationBackend(&events)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := lifecycle.Rotate(ctx, lifecycleSpec(t), store, backend, false); !errors.Is(err, context.Canceled) || len(events) != 0 || store.prepared != 0 {
		t.Error("canceled rotation contacted its backend or prepared artifacts")
	}
}

func TestRetirementLostAcknowledgementRecoversByObservationWithoutRevokingAgain(t *testing.T) {
	events := []string{}
	store, backend := newRotationSession(t, &events), newRotationBackend(&events)
	spec := lifecycleSpec(t)
	if _, err := lifecycle.Rotate(context.Background(), spec, store, backend, false); err != nil {
		t.Fatal("could not prepare the published rotation fixture")
	}
	backend.revokeErr = vault.ErrAccessUnconfirmed
	report, err := lifecycle.Retire(context.Background(), spec, store, backend, true)
	if !errors.Is(err, lifecycle.ErrPartial) || store.receipt.Phase != "pending_retire" || backend.revokes != 1 || store.consumer.Token != "private-new-token" {
		t.Fatal("unknown retirement lost its pending evidence or disturbed the new consumer")
	}
	privateRotationReport(t, report, err)
	// The server applied the first request despite the missing acknowledgement.
	delete(backend.tokens, "private-old-token")
	report, err = lifecycle.Recover(context.Background(), spec, store, backend, false)
	if err != nil || store.receipt.Phase != "retired" || backend.revokes != 1 || !backend.tokens["private-new-token"].Exists {
		t.Error("read-only retirement recovery replayed a revocation or lost the published credential")
	}
	privateRotationReport(t, report, err)
}

func TestUnknownIssuanceCanOnlyBeAbandonedExplicitlyWithTheOldConsumerIntact(t *testing.T) {
	events := []string{}
	store, backend := newRotationSession(t, &events), newRotationBackend(&events)
	spec := lifecycleSpec(t)
	backend.issueErr = vault.ErrAccessUnconfirmed
	if _, err := lifecycle.Rotate(context.Background(), spec, store, backend, false); !errors.Is(err, lifecycle.ErrPartial) {
		t.Fatal("could not prepare an uncertain issuance checkpoint")
	}
	if _, err := lifecycle.Recover(context.Background(), spec, store, backend, false); err == nil || store.receipt.Phase != "prepared" {
		t.Error("recovery silently abandoned or replayed an issuance with no recoverable artifact")
	}
	report, err := lifecycle.Recover(context.Background(), spec, store, backend, true)
	if err != nil || store.receipt.Phase != "aborted" || backend.issues != 1 || backend.logins != 0 || backend.revokes != 0 || store.consumer.Token != "private-old-token" {
		t.Error("explicit abandonment changed the consumer, revoked its working token or issued again")
	}
	privateRotationReport(t, report, err)
}

func TestKnownLiveCandidateCannotBeAbandonedWhileItsCredentialRemainsActive(t *testing.T) {
	events := []string{}
	store, backend := newRotationSession(t, &events), newRotationBackend(&events)
	spec := lifecycleSpec(t)
	backend.probeErr = vault.ErrPermissionDenied
	if _, err := lifecycle.Rotate(context.Background(), spec, store, backend, false); !errors.Is(err, lifecycle.ErrPartial) {
		t.Fatal("could not prepare an unpublished live candidate")
	}
	if _, err := lifecycle.Recover(context.Background(), spec, store, backend, true); err == nil || store.receipt.Phase == "aborted" || backend.revokes != 0 || store.consumer.Token != "private-old-token" {
		t.Error("abandonment forgot an active candidate or automatically revoked a credential")
	}
}

var _ lifecycle.Session = (*rotationSession)(nil)
var _ lifecycle.Backend = (*rotationBackend)(nil)
