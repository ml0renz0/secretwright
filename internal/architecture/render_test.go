package architecture_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/ml0renz0/secretwright/internal/architecture"
	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func f08Instance(kind, id, mount string) map[string]any {
	instance := map[string]any{"id": id, "template": kind, "mount": mount}
	switch kind {
	case "single-user":
		instance["users"] = []string{"alice"}
	case "multi-user":
		instance["users"] = []string{"alice", "bob"}
	case "single-app":
		instance["applications"] = []string{"api"}
	case "multi-app":
		instance["applications"] = []string{"api", "worker"}
	case "multi-env":
		instance["applications"], instance["environments"] = []string{"api", "worker"}, []string{"dev", "prod"}
	case "saas":
		instance["applications"], instance["environments"], instance["tenants"] = []string{"api", "worker"}, []string{"dev", "prod"}, []string{"acme", "globex"}
	}
	return instance
}

func f08Input(t *testing.T, instances ...map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"api_version": "secretwright/architecture/v1", "name": "platform", "instances": instances})
	if err != nil {
		t.Fatal("could not encode the architecture fixture")
	}
	return body
}

func f08Render(t *testing.T, input []byte) ([]byte, blueprint.Document) {
	t.Helper()
	body, err := architecture.Render(bytes.NewReader(input))
	if err != nil || len(body) == 0 || body[len(body)-1] != '\n' || !json.Valid(body) {
		t.Fatal("valid architecture did not render a complete newline-terminated JSON blueprint")
	}
	document, err := blueprint.Load(bytes.NewReader(body), nil)
	if err != nil {
		t.Fatal("rendered architecture is not accepted by the existing blueprint engine")
	}
	return body, document
}

func f08Reject(t *testing.T, input []byte) {
	t.Helper()
	body, err := architecture.Render(bytes.NewReader(input))
	if !errors.Is(err, architecture.ErrInvalidTemplate) || err.Error() != architecture.ErrInvalidTemplate.Error() || len(body) != 0 {
		t.Fatal("invalid architecture exposed a partial result or an input-bearing diagnostic")
	}
}

type f08DenyLoader struct{}

func (f08DenyLoader) Load(string) (any, error) { return nil, errors.New("external schema load forbidden") }

func TestArchitectureCatalogExamplesAndPublishedSchemaStayUsable(t *testing.T) {
	want := []string{"multi-app", "multi-env", "multi-user", "saas", "single-app", "single-user"}
	catalog := architecture.Catalog()
	var names []string
	for _, entry := range catalog {
		names = append(names, entry.Name)
		if strings.TrimSpace(entry.Description) == "" {
			t.Error("catalog omitted the template description")
		}
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatal("catalog omitted a required architecture or changed deterministic ordering")
	}
	catalog[0].Name, catalog[0].Description = "private-mutated-name", "private-mutated-description"
	if next := architecture.Catalog(); next[0].Name != want[0] || strings.Contains(next[0].Description, "private-mutated") {
		t.Error("caller mutation changed the shared catalog")
	}
	artifact, err := os.ReadFile("../../schemas/architecture-v1.schema.json")
	if err != nil || !bytes.Equal(artifact, architecture.Schema()) {
		t.Fatal("runtime schema differs from the published artifact")
	}
	var schemaHeader map[string]any
	if json.Unmarshal(artifact, &schemaHeader) != nil || schemaHeader["$id"] != "urn:secretwright:architecture:v1" || schemaHeader["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatal("architecture schema lost its versioned identifier or Draft 2020-12 dialect")
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(artifact))
	if err != nil {
		t.Fatal("published schema is not JSON")
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(f08DenyLoader{})
	if compiler.AddResource("urn:secretwright:architecture:v1", value) != nil {
		t.Fatal("could not register the published schema")
	}
	compiled, err := compiler.Compile("urn:secretwright:architecture:v1")
	if err != nil {
		t.Fatal("published schema does not compile without external resources")
	}
	for _, name := range want {
		t.Run(name, func(t *testing.T) {
			example, err := architecture.Example(name)
			if err != nil || len(example) == 0 || example[len(example)-1] != '\n' {
				t.Fatal("catalog template has no complete editable example")
			}
			var manifest any
			if json.Unmarshal(example, &manifest) != nil || compiled.Validate(manifest) != nil {
				t.Fatal("catalog example fails the published manifest schema")
			}
			f08Render(t, example)
		})
	}
	if body, err := architecture.Example("private-unknown-template"); !errors.Is(err, architecture.ErrInvalidTemplate) || len(body) != 0 || strings.Contains(err.Error(), "private-unknown") {
		t.Error("unknown template returned a partial example or echoed the name")
	}
	copy := architecture.Schema()
	copy[0] = '!'
	if !bytes.Equal(artifact, architecture.Schema()) {
		t.Error("caller mutation changed the embedded validation schema")
	}
}

func TestAllArchitecturePatternsRenderBoundedBlueprintResourcesOffline(t *testing.T) {
	t.Setenv("VAULT_ADDR", "not-a-vault-url")
	t.Setenv("VAULT_TOKEN", "private-operator-token")
	t.Setenv("VAULT_CLIENT_TIMEOUT", "not-a-duration")
	for _, test := range []struct {
		kind      string
		resources int
		users     int
		roles     int
	}{
		{"single-user", 4, 1, 0}, {"multi-user", 7, 2, 0},
		{"single-app", 3, 0, 1}, {"multi-app", 5, 0, 2},
		{"multi-env", 9, 0, 4}, {"saas", 17, 0, 8},
	} {
		t.Run(test.kind, func(t *testing.T) {
			body, document := f08Render(t, f08Input(t, f08Instance(test.kind, "main", "project/kv")))
			if document.Name != "platform" || len(document.Resources) != test.resources {
				t.Fatal("architecture generated the wrong number of resources")
			}
			byName := make(map[string]blueprint.Resource)
			mountID := ""
			for _, resource := range document.Resources {
				byName[resource.Name] = resource
				if resource.Kind == "kv_mount" {
					mountID = resource.ID
					if resource.Name != "project/kv" || fmt.Sprint(resource.Spec["version"]) != "2" {
						t.Error("architecture changed the declared mount or selected a non-v2 engine")
					}
				}
			}
			counts := make(map[string]int)
			for _, resource := range document.Resources {
				counts[resource.Kind]++
				if resource.Kind == "policy" && !slices.Contains(resource.DependsOn, mountID) {
					t.Error("policy omitted its declared KV mount dependency")
				}
				if resource.Kind == "approle" {
					if resource.Spec["auth_mount"] != "approle" || resource.Spec["token_ttl"] != "15m" || resource.Spec["token_max_ttl"] != "1h" || resource.Spec["secret_id_ttl"] != "1h" || fmt.Sprint(resource.Spec["secret_id_num_uses"]) != "1" || fmt.Sprint(resource.Spec["token_num_uses"]) != "0" {
						t.Error("generated application role lost its explicit bounded defaults")
					}
					policies, ok := resource.Spec["token_policies"].([]any)
					if !ok || len(policies) != 1 {
						t.Fatal("generated role does not select exactly its own explicit policy")
					}
					policy := byName[fmt.Sprint(policies[0])]
					if policy.Kind != "policy" || !slices.Contains(resource.DependsOn, policy.ID) {
						t.Error("generated role omitted its own policy or its dependency edge")
					}
				}
			}
			if counts["kv_mount"] != 1 || counts["entity"] != test.users || counts["group"] != test.users || counts["approle"] != test.roles || counts["policy"] != test.users+test.roles {
				t.Error("architecture generated an unintended resource kind or omitted an access dependency")
			}
			for _, forbidden := range []string{"private-operator-token", `"secret_id":`, `"role_id":`, `"client_token":`, `"ownership":`} {
				if bytes.Contains(body, []byte(forbidden)) {
					t.Error("rendered configuration contains issuance data, operator credentials or future ownership state")
				}
			}
		})
	}
}

func TestArchitectureCompositionIsCanonicalAndSharesOnlyIdenticalMounts(t *testing.T) {
	users := f08Instance("multi-user", "people", "shared")
	apps := f08Instance("multi-env", "services", "shared")
	first, document := f08Render(t, f08Input(t, users, apps))
	users["users"] = []string{"bob", "alice"}
	apps["applications"], apps["environments"] = []string{"worker", "api"}, []string{"prod", "dev"}
	second, _ := f08Render(t, f08Input(t, apps, users))
	if !bytes.Equal(first, second) || len(document.Resources) != 15 {
		t.Fatal("composition depends on input order or duplicated its shared KV mount")
	}
	var ids []string
	for _, resource := range document.Resources {
		ids = append(ids, resource.ID)
	}
	if !slices.IsSorted(ids) {
		t.Error("rendered resource order is not canonical")
	}
	apps["applications"] = []string{"worker", "api", "jobs"}
	_, expanded := f08Render(t, f08Input(t, apps, users))
	byID := make(map[string]blueprint.Resource)
	for _, resource := range expanded.Resources {
		byID[resource.ID] = resource
	}
	for _, resource := range document.Resources {
		if next, present := byID[resource.ID]; !present || !reflect.DeepEqual(resource, next) {
			t.Error("adding a scope renamed or changed a pre-existing resource")
		}
	}
	f08Reject(t, f08Input(t, f08Instance("single-app", "first", "shared"), f08Instance("single-user", "second", "shared/nested")))
	f08Reject(t, f08Input(t, f08Instance("single-app", "same", "one"), f08Instance("single-user", "same", "two")))
}

func f08PolicyPaths(t *testing.T, source string) map[string][]string {
	t.Helper()
	file, err := hcl.Parse(source)
	if err != nil {
		t.Fatal("rendered ACL is not HCL")
	}
	list, ok := file.Node.(*ast.ObjectList)
	if !ok {
		t.Fatal("rendered ACL has no path declarations")
	}
	paths := make(map[string][]string)
	for _, item := range list.Items {
		if len(item.Keys) != 2 || item.Keys[0].Token.Value() != "path" {
			t.Fatal("rendered ACL included an unexpected administrative declaration")
		}
		key, ok := item.Keys[1].Token.Value().(string)
		if !ok {
			t.Fatal("rendered ACL path is not a literal string")
		}
		var rule struct {
			Capabilities []string `hcl:"capabilities"`
		}
		if hcl.DecodeObject(&rule, item.Val) != nil {
			t.Fatal("rendered ACL has invalid capabilities")
		}
		if _, duplicate := paths[key]; duplicate {
			t.Fatal("rendered ACL repeated a path declaration")
		}
		paths[key] = rule.Capabilities
	}
	return paths
}

func TestArchitectureACLAndIdentityGrantsRemainInsideEachScope(t *testing.T) {
	for _, access := range []string{"read", "read-write"} {
		t.Run(access, func(t *testing.T) {
			instance := f08Instance("single-user", "people", "shared/kv")
			instance["access"] = access
			_, document := f08Render(t, f08Input(t, instance))
			var entity, group, policy blueprint.Resource
			for _, resource := range document.Resources {
				switch resource.Kind {
				case "entity":
					entity = resource
				case "group":
					group = resource
				case "policy":
					policy = resource
				}
			}
			capabilities := []string{"read"}
			if access == "read-write" {
				capabilities = []string{"create", "read", "update", "delete"}
			}
			prefix := "shared/kv/"
			scope := "platform/people/users/alice"
			want := map[string][]string{
				prefix + "data/" + scope:           capabilities,
				prefix + "data/" + scope + "/*":    capabilities,
				prefix + "metadata/" + scope:       {"list"},
				prefix + "metadata/" + scope + "/*": {"read", "list"},
			}
			if !reflect.DeepEqual(f08PolicyPaths(t, policy.Spec["policy"].(string)), want) {
				t.Error("generated ACL broadened a scope, listed an ancestor or granted administrative capabilities")
			}
			if !reflect.DeepEqual(entity.Spec["policies"], []any{}) || entity.Spec["disabled"] != false || !reflect.DeepEqual(group.Spec["policies"], []any{policy.Name}) || !reflect.DeepEqual(group.Spec["member_entities"], []any{entity.ID}) || !slices.Contains(group.DependsOn, entity.ID) || !slices.Contains(group.DependsOn, policy.ID) {
				t.Error("user grants bypassed group membership or omitted logical dependencies")
			}
		})
	}
}

func TestArchitectureRejectsAmbiguousOrExecutableInputWithoutEcho(t *testing.T) {
	valid := "api_version: secretwright/architecture/v1\nname: platform\ninstances:\n  - id: main\n    template: single-app\n    mount: project\n    applications: [api]\n"
	f08Render(t, []byte(valid))
	for _, input := range []string{
		strings.Replace(valid, "name: platform", "name: platform\nname: private-repeated", 1),
		strings.Replace(valid, "applications: [api]", "applications: [api]\n    applications: [private-repeated]", 1),
		strings.Replace(valid, "applications: [api]", "applications: &private-anchor [api]", 1),
		strings.Replace(valid, "applications: [api]", "applications: !!binary YXBp", 1),
		strings.Replace(valid, "applications: [api]", "applications: !private-custom [api]", 1),
		strings.Replace(valid, "applications: [api]", "applications: [2026-01-01]", 1),
		strings.Replace(valid, "applications: [api]", "applications: [1e999999999999999999]", 1),
		strings.Replace(valid, "applications: [api]", "applications: [0x61]", 1),
		strings.Replace(valid, "applications: [api]", "applications: [01]", 1),
		strings.Replace(valid, "applications: [api]", "applications: [true]", 1),
		strings.Replace(valid, "mount: project", "mount: ${env.PRIVATE_MARKER}", 1),
		strings.Replace(valid, "mount: project", "mount: https://private.invalid/schema", 1),
		strings.Replace(valid, "mount: project", "mount: project\n    $ref: https://private.invalid/schema", 1),
		strings.Replace(valid, "name: platform", "name: private-marker\x00", 1),
		valid + "---\nprivate-marker: true\n",
		valid + "include: private-marker.yaml\n",
		"[]", "null", "", string([]byte{0xff}),
	} {
		f08Reject(t, []byte(input))
	}
}

func TestArchitectureRejectsUnusedDimensionsInvalidNamesAndExpansions(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"unknown template", func(i map[string]any) { i["template"] = "private-template" }},
		{"empty label", func(i map[string]any) { i["applications"] = []string{""} }},
		{"uppercase label", func(i map[string]any) { i["applications"] = []string{"Private"} }},
		{"slash label", func(i map[string]any) { i["applications"] = []string{"private/scope"} }},
		{"glob label", func(i map[string]any) { i["applications"] = []string{"private*"} }},
		{"long label", func(i map[string]any) { i["applications"] = []string{strings.Repeat("x", 25)} }},
		{"wrong cardinality", func(i map[string]any) { i["applications"] = []string{"api", "worker"} }},
		{"unused users", func(i map[string]any) { i["users"] = []string{} }},
		{"unused environments", func(i map[string]any) { i["environments"] = []string{"dev"} }},
		{"wrong access type", func(i map[string]any) { i["access"] = true }},
		{"unknown access", func(i map[string]any) { i["access"] = "administrator" }},
		{"empty auth mount", func(i map[string]any) { i["auth_mount"] = "" }},
		{"ambiguous auth mount", func(i map[string]any) { i["auth_mount"] = "team/../approle" }},
		{"empty mount", func(i map[string]any) { i["mount"] = "" }},
		{"reserved mount", func(i map[string]any) { i["mount"] = "sys/private" }},
		{"ambiguous mount", func(i map[string]any) { i["mount"] = "team//kv" }},
		{"unknown field", func(i map[string]any) { i["private-marker"] = "private-value" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			instance := f08Instance("single-app", "main", "project")
			test.edit(instance)
			f08Reject(t, f08Input(t, instance))
		})
	}
	for _, kind := range []string{"multi-user", "multi-app", "multi-env", "saas"} {
		instance := f08Instance(kind, "main", "project")
		field := map[string]string{"multi-user": "users", "multi-app": "applications", "multi-env": "environments", "saas": "tenants"}[kind]
		instance[field] = []string{"same", "same"}
		f08Reject(t, f08Input(t, instance))
		instance[field] = []string{"one"}
		f08Reject(t, f08Input(t, instance))
	}
	user := f08Instance("single-user", "main", "project")
	user["auth_mount"] = "approle"
	f08Reject(t, f08Input(t, user))
	large := f08Instance("saas", "main", "project")
	labels := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	large["tenants"], large["applications"], large["environments"] = labels, labels, labels
	f08Reject(t, f08Input(t, large))
	large = f08Instance("multi-user", "main", "project")
	large["users"] = append(append([]string(nil), labels...), "i")
	f08Reject(t, f08Input(t, large))
	instances := make([]map[string]any, 16)
	for index := range instances {
		instances[index] = f08Instance("single-app", fmt.Sprintf("app-%d", index), "shared")
	}
	_, bounded := f08Render(t, f08Input(t, instances...))
	if len(bounded.Resources) != 33 {
		t.Error("maximum instance count duplicated its shared mount")
	}
	f08Reject(t, f08Input(t, append(instances, f08Instance("single-app", "overflow", "shared"))...))
	valid := f08Input(t, f08Instance("single-app", "main", "project"))
	f08Reject(t, append(valid, bytes.Repeat([]byte(" "), blueprint.MaxInputBytes)...))
}

type f08FailedReader struct{}

func (f08FailedReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestArchitectureInputReadFailureNeverReturnsPartialConfiguration(t *testing.T) {
	body, err := architecture.Render(f08FailedReader{})
	if err != architecture.ErrInvalidTemplate || len(body) != 0 {
		t.Fatal("reader failure returned a partial architecture or unfiltered error")
	}
	if body, err := architecture.Render(nil); err != architecture.ErrInvalidTemplate || len(body) != 0 {
		t.Fatal("missing reader returned a partial architecture or unfiltered error")
	}
}
