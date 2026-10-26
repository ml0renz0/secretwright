package managedstate

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	stateID     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	stateName   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	stateHash   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	stateUUID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	stateToken  = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,256}$`)
	stateNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
)

// Validate accepts only the metadata needed to bind an existing resource to its
// last confirmed managed projection. In particular, role credentials cannot be
// stored as a remote ID and arbitrary specs or policy bodies have no field.
func Validate(state State) error {
	if state.APIVersion != APIVersion || !stateName.MatchString(state.Blueprint) || state.Revision == 0 || state.Revision > math.MaxInt64 || state.Resources == nil || len(state.Resources) > MaxResources {
		return ErrInvalidState
	}
	if !stateHash.MatchString(state.Target.AddressSHA256) || !safeText(state.Target.ClusterID, 128) || state.Target.ClusterID == "" || !validNamespace(state.Target.Namespace) {
		return ErrInvalidState
	}
	ids, locators := make(map[string]bool), make(map[string]bool)
	for _, record := range state.Resources {
		if !stateID.MatchString(record.ID) || ids[record.ID] {
			return ErrInvalidState
		}
		ids[record.ID] = true
		if record.Pending != "" && record.Pending != "create" && record.Pending != "update" {
			return ErrInvalidState
		}
		if record.Kind == "kv_mount" {
			if !validMount(record.Name) {
				return ErrInvalidState
			}
			first, _, _ := strings.Cut(record.Name, "/")
			if first == "auth" || first == "sys" || first == "identity" || first == "cubbyhole" {
				return ErrInvalidState
			}
		} else if !stateName.MatchString(record.Name) || record.Kind == "policy" && record.Name == "root" {
			return ErrInvalidState
		}
		switch record.Kind {
		case "approle":
			if !validMount(record.AuthMount) {
				return ErrInvalidState
			}
		case "policy", "entity", "group", "kv_mount":
			if record.AuthMount != "" {
				return ErrInvalidState
			}
		default:
			return ErrInvalidState
		}
		locator := record.Kind + "\x00" + record.Name + "\x00" + record.AuthMount
		if locators[locator] {
			return ErrInvalidState
		}
		locators[locator] = true
		if record.Pending == "create" {
			if record.Fingerprint != "" || record.IdentitySHA256 != "" || record.RemoteID != "" {
				return ErrInvalidState
			}
			continue
		}
		if !stateHash.MatchString(record.Fingerprint) {
			return ErrInvalidState
		}
		if record.Kind == "policy" {
			if record.IdentitySHA256 != "" || record.RemoteID != "" {
				return ErrInvalidState
			}
			continue
		}
		if !stateHash.MatchString(record.IdentitySHA256) {
			return ErrInvalidState
		}
		switch record.Kind {
		case "entity", "group":
			if !stateUUID.MatchString(record.RemoteID) {
				return ErrInvalidState
			}
		case "kv_mount":
			if !stateToken.MatchString(record.RemoteID) {
				return ErrInvalidState
			}
		case "approle":
			if record.RemoteID != "" {
				return ErrInvalidState
			}
		}
	}
	return nil
}

func safeText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && strings.IndexFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) < 0
}

func validMount(value string) bool {
	if value == "" || len(value) > 1024 {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if !stateName.MatchString(segment) {
			return false
		}
	}
	return true
}

func validNamespace(value string) bool {
	if !safeText(value, 1024) || strings.ContainsAny(value, "\\?#") {
		return false
	}
	if value == "" {
		return true
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// Decode consumes one bounded JSON object. It rejects duplicate keys before
// decoding structs, whose standard JSON decoder would otherwise accept them.
func Decode(input io.Reader) (State, error) {
	if input == nil {
		return State{}, ErrInvalidState
	}
	body, err := io.ReadAll(io.LimitReader(input, MaxInputBytes+1))
	if err != nil || len(body) > MaxInputBytes || !utf8.Valid(body) || bytes.IndexByte(body, 0) >= 0 {
		return State{}, ErrInvalidState
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	count := 0
	if !walkJSON(decoder, 0, &count) {
		return State{}, ErrInvalidState
	}
	if _, err := decoder.Token(); err != io.EOF || !validShape(body) {
		return State{}, ErrInvalidState
	}
	decoder = json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var state State
	if decoder.Decode(&state) != nil || Validate(state) != nil {
		return State{}, ErrInvalidState
	}
	return state, nil
}

func walkJSON(decoder *json.Decoder, depth int, count *int) bool {
	*count = *count + 1
	if depth > 32 || *count > 10000 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			keys := make(map[string]bool)
			for decoder.More() {
				key, err := decoder.Token()
				text, ok := key.(string)
				*count = *count + 1
				if err != nil || !ok || strings.ContainsRune(text, 0) || keys[text] || *count > 10000 {
					return false
				}
				keys[text] = true
				if !walkJSON(decoder, depth+1, count) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for decoder.More() {
				if !walkJSON(decoder, depth+1, count) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	case json.Number:
		if !stateNumber.MatchString(string(token)) {
			return false
		}
		_, err := strconv.ParseInt(string(token), 10, 64)
		return err == nil
	case string:
		return !strings.ContainsRune(token, 0)
	case nil, bool:
		return true
	default:
		return false
	}
}

// Standard struct decoding matches names case-insensitively. Check exact keys
// separately so future schema fields cannot acquire accidental aliases.
func validShape(body []byte) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil || !exactKeys(top, []string{"api_version", "blueprint", "target", "revision", "resources"}, nil) {
		return false
	}
	if !stringValue(top["api_version"]) || !stringValue(top["blueprint"]) {
		return false
	}
	var target map[string]json.RawMessage
	if json.Unmarshal(top["target"], &target) != nil || !exactKeys(target, []string{"address_sha256", "cluster_id", "namespace"}, nil) || !stringFields(target) {
		return false
	}
	var records []json.RawMessage
	if json.Unmarshal(top["resources"], &records) != nil {
		return false
	}
	for _, raw := range records {
		var record map[string]json.RawMessage
		if json.Unmarshal(raw, &record) != nil || !exactKeys(record, []string{"id", "kind", "name"}, []string{"auth_mount", "remote_id", "identity_sha256", "baseline_sha256", "pending"}) || !stringFields(record) {
			return false
		}
	}
	return true
}

func stringValue(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '"'
}

func stringFields(object map[string]json.RawMessage) bool {
	for _, raw := range object {
		if !stringValue(raw) {
			return false
		}
	}
	return true
}

func exactKeys(value map[string]json.RawMessage, required, optional []string) bool {
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range required {
		if _, present := value[key]; !present {
			return false
		}
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key := range value {
		if !allowed[key] {
			return false
		}
	}
	return true
}
