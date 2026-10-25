package blueprint_test

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/blueprint"
)

const f07Policy = `path "secret/data/app/*" { capabilities = ["read"] }`

func f07PolicyResource(id string) map[string]any {
	return map[string]any{"id": id, "kind": "policy", "name": "app-" + id, "spec": map[string]any{"policy": f07Policy}}
}

func f07LoadDocument(t *testing.T, resources ...map[string]any) blueprint.Document {
	t.Helper()
	body, err := json.Marshal(map[string]any{"api_version": "secretwright/v1", "name": "app", "resources": resources})
	if err != nil {
		t.Fatal("could not prepare blueprint fixture")
	}
	document, err := blueprint.Load(strings.NewReader(string(body)), nil)
	if err != nil {
		t.Fatal("valid blueprint fixture was rejected")
	}
	return document
}

func f07RequirePrivate(t *testing.T, values ...any) {
	t.Helper()
	for _, value := range values {
		var text string
		if err, ok := value.(error); ok {
			if err == nil {
				continue
			}
			text = err.Error()
		} else {
			body, err := json.Marshal(value)
			if err != nil {
				t.Fatal("could not encode blueprint metadata report")
			}
			text = string(body)
		}
		if strings.Contains(text, "private-f07-") || strings.Contains(text, `"spec"`) || strings.Contains(text, "capabilities =") {
			t.Error("blueprint metadata or error exposed configuration contents")
		}
	}
}

func TestBlueprintParsesTypedVariablesAndDeterministicReferences(t *testing.T) {
	input := `api_version: secretwright/v1
name: ${var.prefix}
variables:
  prefix: {type: string, default: app}
  uses: {type: integer, default: 0}
  disabled: {type: boolean, default: false}
resources:
  - id: team
    kind: group
    name: ${var.prefix}-team
    spec: {member_entities: [person], policies: []}
  - id: role
    kind: approle
    name: ${var.prefix}-role
    spec: {token_policies: [app-read], token_ttl: 5m, token_max_ttl: 1h, secret_id_ttl: 10m, secret_id_num_uses: 1, token_num_uses: "${var.uses}"}
  - id: person
    kind: entity
    name: ${var.prefix}-person
    spec: {disabled: "${var.disabled}"}
`
	document, err := blueprint.Load(strings.NewReader(input), strings.NewReader("prefix: custom\n"))
	if err != nil || document.Name != "custom" || !reflect.DeepEqual(document.Order, []string{"person", "role", "team"}) {
		t.Fatal("typed blueprint variables or deterministic inferred dependencies were incorrect")
	}
	for _, resource := range document.Resources {
		encoded, err := json.Marshal(resource.Spec)
		if err != nil {
			t.Fatal("could not inspect normalized blueprint fixture")
		}
		var data map[string]any
		if err := json.Unmarshal(encoded, &data); err != nil {
			t.Fatal("normalized blueprint data was invalid")
		}
		switch resource.ID {
		case "person":
			if resource.Name != "custom-person" || data["disabled"] != false {
				t.Error("false default was confused with an unset variable")
			}
		case "role":
			if data["token_num_uses"] != float64(0) {
				t.Error("integer zero default was converted to a string or omitted")
			}
		case "team":
			if !reflect.DeepEqual(resource.DependsOn, []string{"person"}) {
				t.Error("logical entity references did not add dependency edges")
			}
		}
	}
	f07RequirePrivate(t, document, document.Resources)
}

func TestBlueprintVariablesAreDeclaredTypedAndExpandedOnlyOnce(t *testing.T) {
	input := `api_version: secretwright/v1
name: app
variables:
  fragment: {type: string}
resources:
  - id: read
    kind: policy
    name: app-read
    spec:
      policy: 'path "${var.fragment}" { capabilities = ["read"] }'
`
	document, err := blueprint.Load(strings.NewReader(input), strings.NewReader(`fragment: '${var.DO_NOT_READ}'`))
	if err != nil || !strings.Contains(document.Resources[0].Spec["policy"].(string), "${var.DO_NOT_READ}") {
		t.Fatal("a variable value was evaluated as a second expression")
	}
	if _, err := blueprint.ValidateDocument(document); err != nil {
		t.Error("validation reinterpreted expressions inside already resolved values")
	}
	for _, overrides := range []string{"", "fragment: 1", "unexpected: private-f07-variable", "fragment: a\nfragment: b\n", "fragment: null"} {
		_, err := blueprint.Load(strings.NewReader(input), strings.NewReader(overrides))
		if !errors.Is(err, blueprint.ErrInvalidBlueprint) {
			t.Error("missing, ambiguous or incorrectly typed variable was accepted")
		}
		f07RequirePrivate(t, err)
	}
	for _, expression := range []string{"${var.missing}", "${env.VAULT_TOKEN}", "${var.fragment", "${unknown}"} {
		_, err := blueprint.Load(strings.NewReader(strings.Replace(input, "${var.fragment}", expression, 1)), strings.NewReader("fragment: app\n"))
		if !errors.Is(err, blueprint.ErrInvalidBlueprint) {
			t.Error("an undeclared or unsupported expression was accepted")
		}
		f07RequirePrivate(t, err)
	}
}

func TestBlueprintRejectsAmbiguousYAMLAndUnsupportedSchemaWithoutEcho(t *testing.T) {
	valid := `{"api_version":"secretwright/v1","name":"app","resources":[{"id":"read","kind":"policy","name":"app-read","spec":{"policy":"path \"secret/*\" { capabilities = [\"read\"] }"}}]}`
	yamlResources := "resources:\n  - id: read\n    kind: policy\n    name: app-read\n    spec: {policy: 'path \"secret/*\" { capabilities = [\"read\"] }'}\n"
	for _, input := range []string{
		strings.Replace(valid, `"name":"app"`, `"name":"app","name":"private-f07-duplicate"`, 1),
		strings.Replace(valid, `"spec":{`, `"spec":{"unexpected":"private-f07-schema",`, 1),
		strings.Replace(valid, `"kind":"policy"`, `"kind":"secret"`, 1),
		strings.Replace(valid, `"api_version":"secretwright/v1"`, `"api_version":"secretwright/v99"`, 1),
		strings.Replace(valid, `"resources":`, `"$schema":"https://invalid.example/private-f07-schema","resources":`, 1),
		valid + "\n---\n" + valid,
		valid + "\xff",
		valid + "\x00",
		"api_version: secretwright/v1\nname: &private-f07-anchor app\n" + yamlResources,
		"api_version: secretwright/v1\nname: *private-f07-alias\n" + yamlResources,
		"api_version: secretwright/v1\nname: !private-f07-tag app\n" + yamlResources,
		"api_version: secretwright/v1\nname: app\n1: private-f07-key\n" + yamlResources,
		"api_version: secretwright/v1\n<<: {name: app}\n" + yamlResources,
		strings.Replace(valid, `"policy":"path`, `"policy":42,"unused":"path`, 1),
	} {
		_, err := blueprint.Load(strings.NewReader(input), nil)
		if !errors.Is(err, blueprint.ErrInvalidBlueprint) {
			t.Error("an ambiguous document or invalid schema instance was accepted")
		}
		f07RequirePrivate(t, err)
	}
	for _, value := range []string{"1.5", "1e999999999999999999999999", "0x10", "010", ".inf", "9223372036854775808"} {
		input := "api_version: secretwright/v1\nname: app\nvariables:\n  count: {type: integer, default: " + value + "}\nresources:\n  - id: read\n    kind: policy\n    name: app-read\n    spec: {policy: 'path \"secret/*\" { capabilities = [\"read\"] }'}\n"
		if _, err := blueprint.Load(strings.NewReader(input), nil); !errors.Is(err, blueprint.ErrInvalidBlueprint) {
			t.Error("an unsupported or unbounded numeric token was accepted")
		}
	}
}

func TestBlueprintRejectsCyclesWrongReferenceKindsAndExpandedTargetCollisions(t *testing.T) {
	for _, resources := range [][]map[string]any{
		{f07PolicyResource("read"), f07PolicyResource("read")},
		{{"id": "read", "kind": "policy", "name": "app-read", "depends_on": []string{"missing"}, "spec": map[string]any{"policy": f07Policy}}},
		{{"id": "a", "kind": "policy", "name": "app-a", "depends_on": []string{"b"}, "spec": map[string]any{"policy": f07Policy}}, {"id": "b", "kind": "policy", "name": "app-b", "depends_on": []string{"a"}, "spec": map[string]any{"policy": f07Policy}}},
		{f07PolicyResource("read"), {"id": "team", "kind": "group", "name": "app-team", "spec": map[string]any{"member_entities": []string{"read"}}}},
		{{"id": "a", "kind": "kv_mount", "name": "app", "spec": map[string]any{"version": 2}}, {"id": "b", "kind": "kv_mount", "name": "app/nested", "spec": map[string]any{"version": 2}}},
		{{"id": "read", "kind": "policy", "name": "App", "spec": map[string]any{"policy": f07Policy}}},
		{{"id": "storage", "kind": "kv_mount", "name": "auth/private-f07-reserved", "spec": map[string]any{"version": 2}}},
	} {
		body, _ := json.Marshal(map[string]any{"api_version": "secretwright/v1", "name": "app", "resources": resources})
		if _, err := blueprint.Load(strings.NewReader(string(body)), nil); !errors.Is(err, blueprint.ErrInvalidBlueprint) {
			t.Error("an unsafe target collision or invalid dependency graph was accepted")
		}
	}
	input := `api_version: secretwright/v1
name: app
variables:
  one: {type: string, default: same}
  two: {type: string, default: same}
resources:
  - {id: a, kind: entity, name: "${var.one}", spec: {}}
  - {id: b, kind: entity, name: "${var.two}", spec: {}}
`
	if _, err := blueprint.Load(strings.NewReader(input), nil); !errors.Is(err, blueprint.ErrInvalidBlueprint) {
		t.Error("target collisions after variable expansion were accepted")
	}
}

func TestBlueprintBoundsInputResourcesAndExpandedConfiguration(t *testing.T) {
	if _, err := blueprint.Load(strings.NewReader(strings.Repeat(" ", (1<<20)+1)), nil); !errors.Is(err, blueprint.ErrInvalidBlueprint) {
		t.Error("oversized blueprint input was accepted")
	}
	resources := make([]map[string]any, 0, 129)
	for index := 0; index < 129; index++ {
		id := "r" + strings.Repeat("a", index/26) + string(rune('a'+index%26))
		resources = append(resources, f07PolicyResource(id))
	}
	body, _ := json.Marshal(map[string]any{"api_version": "secretwright/v1", "name": "app", "resources": resources})
	if _, err := blueprint.Load(strings.NewReader(string(body)), nil); !errors.Is(err, blueprint.ErrInvalidBlueprint) {
		t.Error("blueprint resource limit was silently truncated")
	}
	resources = resources[:0]
	for index := 0; index < 64; index++ {
		id := "r" + strings.Repeat("a", index/26) + string(rune('a'+index%26))
		resource := f07PolicyResource(id)
		resource["spec"] = map[string]any{"policy": `path "` + strings.Repeat("${var.part}", 30) + `" { capabilities = ["read"] }`}
		resources = append(resources, resource)
	}
	body, _ = json.Marshal(map[string]any{"api_version": "secretwright/v1", "name": "app", "variables": map[string]any{"part": map[string]any{"type": "string", "default": strings.Repeat("a", 4096)}}, "resources": resources})
	if _, err := blueprint.Load(strings.NewReader(string(body)), nil); !errors.Is(err, blueprint.ErrInvalidBlueprint) {
		t.Error("expanded blueprint data exceeded its aggregate limit")
	}
}

func TestPublishedBlueprintSchemaAndExampleRemainUsable(t *testing.T) {
	first := blueprint.Schema()
	var schema map[string]any
	if err := json.Unmarshal(first, &schema); err != nil || schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || schema["$id"] != "urn:secretwright:blueprint:v1" {
		t.Fatal("published blueprint schema was not the supported version")
	}
	first[0] = '!'
	if second := blueprint.Schema(); len(second) == 0 || second[0] == '!' {
		t.Error("a caller could mutate the embedded schema")
	}
	example, err := os.Open("../../examples/blueprints/app.yaml")
	if err != nil {
		t.Fatal("could not open the published blueprint example")
	}
	defer example.Close()
	if _, err := blueprint.Load(example, nil); err != nil {
		t.Error("the published blueprint example did not validate against its schema")
	}
}
