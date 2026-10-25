// Package blueprint validates and applies non-secret declarative Vault resources.
package blueprint

import "errors"

const (
	APIVersion       = "secretwright/v1"
	MaxInputBytes    = 1 << 20
	MaxExpandedBytes = 4 << 20
	MaxResources     = 128
	MaxVariables     = 64
	MaxNodes         = 10000
	MaxDepth         = 64
	MaxStringBytes   = 128 << 10
	MaxVariableBytes = 4096
)

var ErrInvalidBlueprint = errors.New("invalid or oversized Secretwright blueprint or variables")

// Spec is deliberately omitted from ordinary JSON reports. Reports may identify
// resources, but never dump configuration, policy text or variable values.
type Resource struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Name      string         `json:"name"`
	DependsOn []string       `json:"depends_on,omitempty"`
	Spec      map[string]any `json:"-"`
}

type Document struct {
	APIVersion string     `json:"-"`
	Name       string     `json:"name"`
	Resources  []Resource `json:"-"`
	Order      []string   `json:"order"`
}

type ValidationReport struct {
	Name      string   `json:"name"`
	Resources int      `json:"resources"`
	Order     []string `json:"order"`
}
