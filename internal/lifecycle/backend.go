package lifecycle

import (
 "context"
 "crypto/subtle"
 "encoding/json"
 "strings"

 "github.com/ml0renz0/secretwright/internal/managedstate"
 "github.com/ml0renz0/secretwright/internal/vault"
)

// VaultBackend keeps the operator separate from every consumer credential.
type VaultBackend struct { client *vault.Client; operator string }

func NewVaultBackend(client *vault.Client, operator string) *VaultBackend { return &VaultBackend{client: client, operator: strings.TrimSpace(operator)} }
func (b *VaultBackend) Target(ctx context.Context) (managedstate.Target, error) {
 if b == nil || b.client == nil { return managedstate.Target{}, ErrConflict }
 target, err := b.client.ReconciliationTarget(ctx)
 if err != nil { return managedstate.Target{}, safeError(err) }
 return managedstate.Target{AddressSHA256: target.AddressSHA256, ClusterID: target.ClusterID, Namespace: target.Namespace}, nil
}
func (b *VaultBackend) Role(ctx context.Context, spec Spec) (RoleInfo, error) {
 state, err := b.client.ReadReconciliationAppRole(ctx, b.operator, spec.Provider.Role, vault.AppRoleOptions{Mount: spec.Provider.AuthMount})
 if err != nil { return RoleInfo{}, safeError(err) }
 id, err := b.client.ReadAppRoleID(ctx, b.operator, spec.Provider.Role, vault.AppRoleOptions{Mount: spec.Provider.AuthMount})
 if err != nil { return RoleInfo{}, safeError(err) }
 body, err := json.Marshal([]string{id, state.State.AuthMountAccessor})
 if err != nil || digestBytes(body) != state.Identity { return RoleInfo{}, ErrConflict }
 return RoleInfo{State: state.State, Identity: state.Identity, RoleID: id}, nil
}
func (b *VaultBackend) Token(ctx context.Context, token string) (vault.TokenLifecycleInfo, error) { return b.client.InspectLifecycleToken(ctx, b.operator, token) }
func (b *VaultBackend) IsOperator(token string) bool { return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(token)), []byte(b.operator)) == 1 }
func (b *VaultBackend) Issue(ctx context.Context, spec Spec) (vault.AppRoleCredentials, error) { return b.client.IssueAppRoleCredentials(ctx, b.operator, spec.Provider.Role, vault.AppRoleOptions{Mount: spec.Provider.AuthMount}) }
func (b *VaultBackend) Login(ctx context.Context, spec Spec, credentials vault.AppRoleCredentials) (vault.IssuedToken, error) { return b.client.LoginAppRole(ctx, credentials, vault.AppRoleOptions{Mount: spec.Provider.AuthMount}) }
func (b *VaultBackend) Probe(ctx context.Context, spec Spec, token string) error { _, err := b.client.Read(ctx, token, spec.Verify.Path, vault.KVOptions{Mount: spec.Verify.Mount, Version: 2}); return safeError(err) }
func (b *VaultBackend) Revoke(ctx context.Context, token string) error { _, err := b.client.RevokeToken(ctx, b.operator, token); return safeError(err) }

var _ Backend = (*VaultBackend)(nil)
