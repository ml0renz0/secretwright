package architecture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/ml0renz0/secretwright/internal/blueprint"
)

// Render expands a bounded architecture into a complete, canonical F07
// blueprint. It only uses the supplied configuration; no credentials or Vault
// clients are selected while rendering.
func Render(input io.Reader) ([]byte, error) {
	manifest, err := parseManifest(input)
	if err != nil || !withinResourceBudget(manifest) {
		return nil, ErrInvalidTemplate
	}
	builder := architectureBuilder{name: manifest.Name, resources: make(map[string]blueprint.Resource)}
	mounts := make(map[string]bool)
	for _, instance := range manifest.Instances {
		mountID := "mount_" + scopeDigest(instance.Mount)
		if !mounts[instance.Mount] {
			if !builder.add(blueprint.Resource{ID: mountID, Kind: "kv_mount", Name: instance.Mount, Spec: map[string]any{"version": 2}}) {
				return nil, ErrInvalidTemplate
			}
			mounts[instance.Mount] = true
		}
		if !builder.expand(instance, mountID) {
			return nil, ErrInvalidTemplate
		}
	}
	document := blueprint.Document{APIVersion: blueprint.APIVersion, Name: manifest.Name, Resources: make([]blueprint.Resource, 0, len(builder.resources))}
	for _, resource := range builder.resources {
		document.Resources = append(document.Resources, resource)
	}
	sort.Slice(document.Resources, func(i, j int) bool { return document.Resources[i].ID < document.Resources[j].ID })
	document, err = blueprint.ValidateDocument(document)
	if err != nil {
		return nil, ErrInvalidTemplate
	}
	return marshalBlueprint(document)
}

// Count before constructing any Cartesian product. Dimensions are bounded by
// the manifest schema, and division keeps this check safe even if those bounds
// are widened later.
func withinResourceBudget(manifest Manifest) bool {
	mounts := make(map[string]bool)
	for _, instance := range manifest.Instances {
		mounts[instance.Mount] = true
	}
	total := len(mounts)
	if total > blueprint.MaxResources {
		return false
	}
	for _, instance := range manifest.Instances {
		count, multiplier := 0, 2
		switch instance.Template {
		case "single-user", "multi-user":
			count, multiplier = len(instance.Users), 3
		case "single-app", "multi-app":
			count = len(instance.Applications)
		case "multi-env":
			count = boundedProduct(len(instance.Applications), len(instance.Environments))
		case "saas":
			count = boundedProduct(len(instance.Applications), len(instance.Environments), len(instance.Tenants))
		default:
			return false
		}
		if count <= 0 || count > (blueprint.MaxResources-total)/multiplier {
			return false
		}
		total += count * multiplier
	}
	return total > 0
}

func boundedProduct(dimensions ...int) int {
	product := 1
	for _, dimension := range dimensions {
		if dimension <= 0 || dimension > blueprint.MaxResources/product {
			return 0
		}
		product *= dimension
	}
	return product
}

type architectureBuilder struct {
	name      string
	resources map[string]blueprint.Resource
}

// Shared mounts are coalesced explicitly by Render. Every other duplicate ID,
// including a truncated-hash collision, rejects the whole render.
func (builder *architectureBuilder) add(resource blueprint.Resource) bool {
	if _, present := builder.resources[resource.ID]; present || len(builder.resources) >= blueprint.MaxResources {
		return false
	}
	builder.resources[resource.ID] = resource
	return true
}

func (builder *architectureBuilder) expand(instance Instance, mountID string) bool {
	prefix := builder.name + "/" + instance.ID
	switch instance.Template {
	case "single-user", "multi-user":
		for _, user := range instance.Users {
			if !builder.addScope(instance, mountID, prefix+"/users/"+user, user, true) {
				return false
			}
		}
	case "single-app", "multi-app":
		for _, application := range instance.Applications {
			if !builder.addScope(instance, mountID, prefix+"/apps/"+application, application, false) {
				return false
			}
		}
	case "multi-env":
		for _, environment := range instance.Environments {
			for _, application := range instance.Applications {
				scope := prefix + "/envs/" + environment + "/apps/" + application
				if !builder.addScope(instance, mountID, scope, application, false) {
					return false
				}
			}
		}
	case "saas":
		for _, tenant := range instance.Tenants {
			for _, environment := range instance.Environments {
				for _, application := range instance.Applications {
					scope := prefix + "/tenants/" + tenant + "/envs/" + environment + "/apps/" + application
					if !builder.addScope(instance, mountID, scope, application, false) {
						return false
					}
				}
			}
		}
	default:
		return false
	}
	return true
}

func (builder *architectureBuilder) addScope(instance Instance, mountID, scope, principal string, user bool) bool {
	digest := scopeDigest(scope)
	stem := builder.name + "-" + instance.ID + "-" + principal + "-" + digest
	policyID, policyName := "policy_"+digest, stem+"-access"
	if !builder.add(blueprint.Resource{
		ID: policyID, Kind: "policy", Name: policyName, DependsOn: []string{mountID},
		Spec: map[string]any{"policy": scopePolicy(instance.Mount, scope, instance.Access)},
	}) {
		return false
	}
	if user {
		entityID := "entity_" + digest
		if !builder.add(blueprint.Resource{
			ID: entityID, Kind: "entity", Name: stem + "-user",
			Spec: map[string]any{"disabled": false, "policies": []string{}},
		}) {
			return false
		}
		return builder.add(blueprint.Resource{
			ID: "group_" + digest, Kind: "group", Name: stem + "-group", DependsOn: []string{entityID, policyID},
			Spec: map[string]any{"policies": []string{policyName}, "member_entities": []string{entityID}, "member_groups": []string{}},
		})
	}
	return builder.add(blueprint.Resource{
		ID: "role_" + digest, Kind: "approle", Name: stem + "-app", DependsOn: []string{policyID},
		Spec: map[string]any{
			"auth_mount": instance.AuthMount, "token_policies": []string{policyName},
			"token_ttl": "15m", "token_max_ttl": "1h", "secret_id_ttl": "1h",
			"secret_id_num_uses": 1, "token_num_uses": 0,
		},
	})
}

func scopeDigest(scope string) string {
	digest := sha256.Sum256([]byte(scope))
	return hex.EncodeToString(digest[:8])
}

func scopePolicy(mount, scope, access string) string {
	dataCapabilities := `["read"]`
	if access == "read-write" {
		dataCapabilities = `["create", "read", "update", "delete"]`
	}
	return fmt.Sprintf("path %q { capabilities = %s }\npath %q { capabilities = %s }\npath %q { capabilities = [\"list\"] }\npath %q { capabilities = [\"read\", \"list\"] }\n",
		mount+"/data/"+scope, dataCapabilities,
		mount+"/data/"+scope+"/*", dataCapabilities,
		mount+"/metadata/"+scope,
		mount+"/metadata/"+scope+"/*",
	)
}

// Blueprint report types intentionally omit specs and resources. Rendering is
// an explicit configuration export, so use a dedicated DTO rather than changing
// those report types or weakening their privacy guarantees.
type renderedBlueprint struct {
	APIVersion string             `json:"api_version"`
	Name       string             `json:"name"`
	Resources  []renderedResource `json:"resources"`
}

type renderedResource struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Name      string         `json:"name"`
	DependsOn []string       `json:"depends_on,omitempty"`
	Spec      map[string]any `json:"spec"`
}

func marshalBlueprint(document blueprint.Document) ([]byte, error) {
	output := renderedBlueprint{APIVersion: document.APIVersion, Name: document.Name, Resources: make([]renderedResource, 0, len(document.Resources))}
	for _, resource := range document.Resources {
		output.Resources = append(output.Resources, renderedResource{
			ID: resource.ID, Kind: resource.Kind, Name: resource.Name, DependsOn: resource.DependsOn, Spec: resource.Spec,
		})
	}
	body, err := json.MarshalIndent(output, "", "  ")
	if err != nil || len(body)+1 > blueprint.MaxExpandedBytes {
		return nil, ErrInvalidTemplate
	}
	body = append(body, '\n')
	if _, err := blueprint.Load(bytes.NewReader(body), nil); err != nil {
		return nil, ErrInvalidTemplate
	}
	return body, nil
}
