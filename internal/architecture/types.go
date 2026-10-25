// Package architecture renders bounded, offline architecture manifests into
// blueprints accepted by the existing declarative engine.
package architecture

import "errors"

const APIVersion = "secretwright/architecture/v1"

var ErrInvalidTemplate = errors.New("invalid or oversized Secretwright architecture manifest or template")

type Template struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type Manifest struct {
	APIVersion string     `json:"api_version"`
	Name       string     `json:"name"`
	Instances  []Instance `json:"instances"`
}

type Instance struct {
	ID           string   `json:"id"`
	Template     string   `json:"template"`
	Mount        string   `json:"mount"`
	AuthMount    string   `json:"auth_mount,omitempty"`
	Access       string   `json:"access,omitempty"`
	Users        []string `json:"users,omitempty"`
	Applications []string `json:"applications,omitempty"`
	Environments []string `json:"environments,omitempty"`
	Tenants      []string `json:"tenants,omitempty"`
}
