package blueprint

import (
	"bytes"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/hcl/printer"
	"github.com/ml0renz0/secretwright/internal/vault"
)

var (
	resourceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	resourceID   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
)

// ValidateDocument rechecks constructed, already resolved documents without
// interpreting string values as variables again. It returns detached data.
func ValidateDocument(document Document) (Document, error) {
	if document.APIVersion != APIVersion || len(document.Resources) == 0 || len(document.Resources) > MaxResources {
		return Document{}, ErrInvalidBlueprint
	}
	object := documentEnvelope(document)
	count := 0
	detached, err := detachJSON(object, 0, &count)
	if err != nil {
		return Document{}, ErrInvalidBlueprint
	}
	encoded, err := json.Marshal(detached)
	if err != nil || len(encoded) > MaxExpandedBytes || validateSchema(detached, false) != nil {
		return Document{}, ErrInvalidBlueprint
	}
	normalized, err := documentFromObject(detached.(map[string]any))
	if err != nil {
		return Document{}, ErrInvalidBlueprint
	}
	for index := range normalized.Resources {
		if err := normalizeResource(&normalized.Resources[index]); err != nil {
			return Document{}, ErrInvalidBlueprint
		}
	}
	if err := normalizeGraph(&normalized); err != nil {
		return Document{}, ErrInvalidBlueprint
	}
	// Added graph edges, defaults and formatted HCL must remain inside the
	// same bounds when the normalized document is validated again by Apply.
	count = 0
	final, err := detachJSON(documentEnvelope(normalized), 0, &count)
	if err != nil {
		return Document{}, ErrInvalidBlueprint
	}
	encoded, err = json.Marshal(final)
	if err != nil || len(encoded) > MaxExpandedBytes {
		return Document{}, ErrInvalidBlueprint
	}
	return normalized, nil
}

func documentEnvelope(document Document) map[string]any {
	resources := make([]any, 0, len(document.Resources))
	for _, resource := range document.Resources {
		item := map[string]any{"id": resource.ID, "kind": resource.Kind, "name": resource.Name, "spec": resource.Spec}
		if len(resource.DependsOn) != 0 {
			item["depends_on"] = resource.DependsOn
		}
		resources = append(resources, item)
	}
	return map[string]any{"api_version": document.APIVersion, "name": document.Name, "resources": resources}
}

func detachJSON(value any, depth int, count *int) (any, error) {
	*count = *count + 1
	if depth > MaxDepth || *count > MaxNodes {
		return nil, ErrInvalidBlueprint
	}
	switch value := value.(type) {
	case nil, bool:
		return value, nil
	case string:
		if !validString(value) {
			return nil, ErrInvalidBlueprint
		}
		return value, nil
	case []string:
		items := make([]any, len(value))
		for index, item := range value {
			items[index] = item
		}
		return detachJSON(items, depth, count)
	case []any:
		result := make([]any, len(value))
		for index, item := range value {
			child, err := detachJSON(item, depth+1, count)
			if err != nil {
				return nil, err
			}
			result[index] = child
		}
		return result, nil
	case map[string]any:
		result := make(map[string]any, len(value))
		for key, item := range value {
			*count = *count + 1
			if *count > MaxNodes || !validString(key) {
				return nil, ErrInvalidBlueprint
			}
			child, err := detachJSON(item, depth+1, count)
			if err != nil {
				return nil, err
			}
			result[key] = child
		}
		return result, nil
	case json.Number, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		if number, ok := value.(float64); ok && (math.IsInf(number, 0) || math.IsNaN(number)) {
			return nil, ErrInvalidBlueprint
		}
		body, err := json.Marshal(value)
		if err != nil || !decimalInteger.Match(body) {
			return nil, ErrInvalidBlueprint
		}
		if _, err := strconv.ParseInt(string(body), 10, 64); err != nil {
			return nil, ErrInvalidBlueprint
		}
		return json.Number(string(body)), nil
	default:
		return nil, ErrInvalidBlueprint
	}
}

// NormalizePolicy checks syntax and formats policy HCL locally. Vault remains
// responsible for the ACL meaning; formatting is not semantic equivalence.
func NormalizePolicy(policy string) (string, error) {
	if !validString(policy) || strings.TrimSpace(policy) == "" {
		return "", ErrInvalidBlueprint
	}
	formatted, err := printer.Format([]byte(policy))
	if err != nil || len(formatted) > MaxStringBytes {
		return "", ErrInvalidBlueprint
	}
	return string(formatted), nil
}

func normalizeResource(resource *Resource) error {
	if !resourceID.MatchString(resource.ID) {
		return ErrInvalidBlueprint
	}
	switch resource.Kind {
	case "kv_mount":
		if !validMountName(resource.Name) {
			return ErrInvalidBlueprint
		}
		first := strings.Split(resource.Name, "/")[0]
		if first == "auth" || first == "sys" || first == "identity" || first == "cubbyhole" {
			return ErrInvalidBlueprint
		}
		return nil
	case "policy":
		if resource.Name == "root" {
			return ErrInvalidBlueprint
		}
		policy, ok := resource.Spec["policy"].(string)
		if !ok {
			return ErrInvalidBlueprint
		}
		normalized, err := NormalizePolicy(policy)
		if err != nil {
			return err
		}
		resource.Spec = map[string]any{"policy": normalized}
		return nil
	case "approle":
		mount := "approle"
		if value, present := resource.Spec["auth_mount"]; present {
			var ok bool
			mount, ok = value.(string)
			if !ok || !validMountName(mount) {
				return ErrInvalidBlueprint
			}
		}
		input := copySpec(resource.Spec)
		delete(input, "auth_mount")
		body, err := json.Marshal(input)
		if err != nil {
			return ErrInvalidBlueprint
		}
		spec, err := vault.DecodeRoleSpec(bytes.NewReader(body))
		if err != nil || !lowerPolicyNames(spec.TokenPolicies) {
			return ErrInvalidBlueprint
		}
		resource.Spec, err = normalizedSpec(spec)
		if err != nil {
			return err
		}
		resource.Spec["auth_mount"] = mount
		return nil
	case "entity":
		input := copySpec(resource.Spec)
		input["name"] = resource.Name
		body, err := json.Marshal(input)
		if err != nil {
			return ErrInvalidBlueprint
		}
		spec, err := vault.DecodeEntitySpec(bytes.NewReader(body))
		if err != nil || !lowerPolicyNames(spec.Policies) {
			return ErrInvalidBlueprint
		}
		resource.Spec, err = normalizedSpec(spec)
		delete(resource.Spec, "name")
		return err
	case "group":
		entities, err := stringValues(resource.Spec["member_entities"])
		if err != nil {
			return err
		}
		groups, err := stringValues(resource.Spec["member_groups"])
		if err != nil {
			return err
		}
		input := copySpec(resource.Spec)
		delete(input, "member_entities")
		delete(input, "member_groups")
		input["name"] = resource.Name
		body, err := json.Marshal(input)
		if err != nil {
			return ErrInvalidBlueprint
		}
		spec, err := vault.DecodeGroupSpec(bytes.NewReader(body))
		if err != nil || !lowerPolicyNames(spec.Policies) {
			return ErrInvalidBlueprint
		}
		entities, groups = sortedUnique(entities), sortedUnique(groups)
		if len(entities)+len(spec.MemberEntityIDs) > 1000 || len(groups)+len(spec.MemberGroupIDs) > 1000 {
			return ErrInvalidBlueprint
		}
		resource.Spec, err = normalizedSpec(spec)
		if err != nil {
			return err
		}
		delete(resource.Spec, "name")
		resource.Spec["member_entities"] = toAnyStrings(entities)
		resource.Spec["member_groups"] = toAnyStrings(groups)
		return nil
	}
	return ErrInvalidBlueprint
}

func validMountName(value string) bool {
	if len(value) == 0 || len(value) > 1024 {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if !resourceName.MatchString(segment) {
			return false
		}
	}
	return true
}

func lowerPolicyNames(names []string) bool {
	for _, name := range names {
		if !resourceName.MatchString(name) {
			return false
		}
	}
	return true
}

func copySpec(spec map[string]any) map[string]any {
	result := make(map[string]any, len(spec))
	for key, value := range spec {
		result[key] = value
	}
	return result
}

func normalizedSpec(value any) (map[string]any, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidBlueprint
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var result map[string]any
	if decoder.Decode(&result) != nil {
		return nil, ErrInvalidBlueprint
	}
	return result, nil
}

func sortedUnique(values []string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		unique[value] = struct{}{}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func toAnyStrings(values []string) []any {
	result := make([]any, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

func normalizeGraph(document *Document) error {
	sort.Slice(document.Resources, func(i, j int) bool { return document.Resources[i].ID < document.Resources[j].ID })
	indices := make(map[string]int, len(document.Resources))
	locators := make(map[string]struct{}, len(document.Resources))
	mounts := []string{}
	for index, resource := range document.Resources {
		if _, duplicate := indices[resource.ID]; duplicate {
			return ErrInvalidBlueprint
		}
		indices[resource.ID] = index
		locator := resource.Kind + "\x00" + resource.Name
		if resource.Kind == "approle" {
			mount, ok := resource.Spec["auth_mount"].(string)
			if !ok {
				return ErrInvalidBlueprint
			}
			locator += "\x00" + mount
		}
		if _, duplicate := locators[locator]; duplicate {
			return ErrInvalidBlueprint
		}
		locators[locator] = struct{}{}
		if resource.Kind == "kv_mount" {
			for _, mount := range mounts {
				if resource.Name == mount || strings.HasPrefix(resource.Name, mount+"/") || strings.HasPrefix(mount, resource.Name+"/") {
					return ErrInvalidBlueprint
				}
			}
			mounts = append(mounts, resource.Name)
		}
	}
	for index := range document.Resources {
		resource := &document.Resources[index]
		dependencies := append([]string(nil), resource.DependsOn...)
		if resource.Kind == "group" {
			for key, kind := range map[string]string{"member_entities": "entity", "member_groups": "group"} {
				references, err := stringValues(resource.Spec[key])
				if err != nil {
					return err
				}
				for _, id := range references {
					other, exists := indices[id]
					if !exists || document.Resources[other].Kind != kind {
						return ErrInvalidBlueprint
					}
					dependencies = append(dependencies, id)
				}
			}
		}
		resource.DependsOn = sortedUnique(dependencies)
		for _, id := range resource.DependsOn {
			if _, exists := indices[id]; !exists || id == resource.ID {
				return ErrInvalidBlueprint
			}
		}
	}
	order := make([]string, 0, len(document.Resources))
	complete := make(map[string]bool, len(document.Resources))
	for len(order) < len(document.Resources) {
		chosen := ""
		for _, resource := range document.Resources {
			if complete[resource.ID] {
				continue
			}
			ready := true
			for _, dependency := range resource.DependsOn {
				if !complete[dependency] {
					ready = false
					break
				}
			}
			if ready {
				chosen = resource.ID
				break
			}
		}
		if chosen == "" {
			return ErrInvalidBlueprint
		}
		order = append(order, chosen)
		complete[chosen] = true
	}
	document.Order = order
	return nil
}
