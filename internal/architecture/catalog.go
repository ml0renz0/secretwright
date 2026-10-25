package architecture

import "encoding/json"

// Catalog returns a detached, deterministically ordered description of the
// fixed local templates. It never discovers external templates.
func Catalog() []Template {
	return []Template{
		{Name: "multi-app", Description: "Isolated application scopes and bounded AppRoles in one KV v2 mount."},
		{Name: "multi-env", Description: "Application scopes isolated across environments, with one bounded AppRole per scope."},
		{Name: "multi-user", Description: "Isolated user workspaces with entity and group grants; authentication binding is external."},
		{Name: "saas", Description: "Tenant, environment and application scopes isolated by bounded AppRoles."},
		{Name: "single-app", Description: "One application scope and a bounded AppRole in a KV v2 mount."},
		{Name: "single-user", Description: "One user workspace with entity and group grants; authentication binding is external."},
	}
}

// Example returns an editable architecture manifest, never a credential bundle.
func Example(name string) ([]byte, error) {
	manifest := Manifest{
		APIVersion: APIVersion,
		Name:       "example",
		Instances:  []Instance{{ID: "main", Template: name, Mount: "example", Access: "read"}},
	}
	instance := &manifest.Instances[0]
	switch name {
	case "single-user":
		instance.Users = []string{"alice"}
	case "multi-user":
		instance.Users = []string{"alice", "bob"}
	case "single-app":
		instance.Applications = []string{"api"}
	case "multi-app":
		instance.Applications = []string{"api", "worker"}
	case "multi-env":
		instance.Applications = []string{"api", "worker"}
		instance.Environments = []string{"dev", "prod"}
	case "saas":
		instance.Applications = []string{"api", "worker"}
		instance.Environments = []string{"dev", "prod"}
		instance.Tenants = []string{"acme", "globex"}
	default:
		return nil, ErrInvalidTemplate
	}
	if len(instance.Applications) != 0 {
		instance.AuthMount = "approle"
	}
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, ErrInvalidTemplate
	}
	return append(body, '\n'), nil
}
