// Package lifecycle performs bounded, explicitly acknowledged credential
// rotation with a private file consumer and recoverable local checkpoints.
package lifecycle

import (
	"context"
	"errors"

	"github.com/ml0renz0/secretwright/internal/fileformat"
	"github.com/ml0renz0/secretwright/internal/managedstate"
	"github.com/ml0renz0/secretwright/internal/vault"
)

const (
	APIVersion     = "secretwright/lifecycle/v1"
	ReceiptVersion = "secretwright/rotation/v1"
)

var (
	ErrInvalidLifecycle = errors.New("invalid or oversized Secretwright lifecycle configuration or receipt")
	ErrConflict         = errors.New("lifecycle binding, private file, role, or pending checkpoint conflicts with this operation")
	ErrPartial          = errors.New("lifecycle operation is incomplete; inspect its private receipt before retrying")
	ErrUnconfirmed      = errors.New("lifecycle outcome could not be confirmed; inspect its private receipt before retrying")
	ErrIO               = errors.New("could not read or persist private lifecycle files")
)

type Spec struct {
	APIVersion string       `json:"api_version" yaml:"api_version"`
	Name       string       `json:"name" yaml:"name"`
	Provider   ProviderSpec `json:"provider" yaml:"provider"`
	Consumer   ConsumerSpec `json:"consumer" yaml:"consumer"`
	Verify     VerifySpec   `json:"verify" yaml:"verify"`
	Policy     PolicySpec   `json:"policy" yaml:"policy"`
}

type ProviderSpec struct {
	Kind      string `json:"kind" yaml:"kind"`
	AuthMount string `json:"auth_mount" yaml:"auth_mount"`
	Role      string `json:"role" yaml:"role"`
}

type ConsumerSpec struct {
	Kind string `json:"kind" yaml:"kind"`
	Path string `json:"path" yaml:"path"`
}

type VerifySpec struct {
	Kind      string `json:"kind" yaml:"kind"`
	Mount     string `json:"mount" yaml:"mount"`
	KVVersion int    `json:"kv_version" yaml:"kv_version"`
	Path      string `json:"path" yaml:"path"`
}

type PolicySpec struct {
	RotateBelow   string `json:"rotate_below" yaml:"rotate_below"`
	MinimumNewTTL string `json:"minimum_new_ttl" yaml:"minimum_new_ttl"`
}

// PrivateFile must never become ordinary JSON output. Data is retained only
// in private generation artifacts; receipt hashes describe its exact bytes.
type PrivateFile struct {
	Data   []byte `json:"-" yaml:"-"`
	Token  string `json:"-" yaml:"-"`
	Digest string `json:"-" yaml:"-"`
}

type Receipt struct {
	APIVersion   string              `json:"api_version" yaml:"api_version"`
	Name         string              `json:"name" yaml:"name"`
	ConfigSHA256 string              `json:"config_sha256" yaml:"config_sha256"`
	Target       managedstate.Target `json:"target" yaml:"target"`
	Revision     uint64              `json:"revision" yaml:"revision"`
	Generation   string              `json:"generation" yaml:"generation"`
	Phase        string              `json:"phase" yaml:"phase"`
	RoleIdentity string              `json:"role_identity" yaml:"role_identity"`
	OldDigest    string              `json:"old_digest" yaml:"old_digest"`
	NewDigest    string              `json:"new_digest,omitempty" yaml:"new_digest,omitempty"`
	BundleDigest string              `json:"bundle_digest,omitempty" yaml:"bundle_digest,omitempty"`
	EntityID     string              `json:"entity_id" yaml:"entity_id"`
	Format       fileformat.Format   `json:"format" yaml:"format"`
}

type Session interface {
	Snapshot() Receipt
	Consumer() (PrivateFile, error)
	Prepare(Receipt, PrivateFile) error
	Save(Receipt) error
	Put(string, []byte) error
	Load(string) (PrivateFile, error)
	Publish(string) error
}

type RoleInfo struct {
	State    vault.BlueprintAppRoleState `json:"-" yaml:"-"`
	Identity string                      `json:"-" yaml:"-"`
	RoleID   string                      `json:"-" yaml:"-"`
}

type Backend interface {
	Target(context.Context) (managedstate.Target, error)
	Role(context.Context, Spec) (RoleInfo, error)
	Token(context.Context, string) (vault.TokenLifecycleInfo, error)
	IsOperator(string) bool
	Issue(context.Context, Spec) (vault.AppRoleCredentials, error)
	Login(context.Context, Spec, vault.AppRoleCredentials) (vault.IssuedToken, error)
	Probe(context.Context, Spec, string) error
	Revoke(context.Context, string) error
}

type Report struct {
	Name       string `json:"name"`
	Operation  string `json:"operation"`
	Phase      string `json:"phase"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
	Renewable  bool   `json:"renewable"`
	Due        bool   `json:"due"`
}
