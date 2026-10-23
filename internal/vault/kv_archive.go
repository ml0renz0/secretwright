package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

var (
	ErrInvalidArchive     = errors.New("invalid or oversized Secretwright KV archive")
	errInvalidReplaceRule = errors.New("replacement rule must contain only nonempty match and replacement JSON objects, at most 1 MiB")
	errArchiveWrite       = errors.New("could not write the KV archive")
	errStrictJSON         = errors.New("invalid JSON object")
)

// ArchiveEntry stores a relative Vault key, independently of local filesystem
// paths. A key named foo may coexist with another key named foo/bar.
type ArchiveEntry struct {
	Path string         `json:"path"`
	Data map[string]any `json:"data"`
}

// Archive includes only current KV values. Root is informational: restoring an
// archive always requires a separate destination chosen by its caller.
type Archive struct {
	Format  string         `json:"format"`
	Version int            `json:"version"`
	Root    string         `json:"root"`
	Entries []ArchiveEntry `json:"entries"`
}

// DecodeArchive validates a bounded archive in full before it can be used to
// select credentials, contact Vault, or write any destination.
func DecodeArchive(input io.Reader) (Archive, error) {
	body, err := readBoundedJSON(input, MaxArchiveBytes)
	if err != nil {
		return Archive{}, ErrInvalidArchive
	}
	value, err := decodeStrictJSON(body)
	if err != nil {
		return Archive{}, ErrInvalidArchive
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 4 {
		return Archive{}, ErrInvalidArchive
	}
	format, formatOK := object["format"].(string)
	version, versionOK := object["version"].(json.Number)
	root, rootOK := object["root"].(string)
	entries, entriesOK := object["entries"].([]any)
	if !formatOK || !versionOK || version.String() != "1" || !rootOK || !entriesOK {
		return Archive{}, ErrInvalidArchive
	}
	archive := Archive{Format: format, Version: 1, Root: root, Entries: make([]ArchiveEntry, 0, len(entries))}
	for _, value := range entries {
		entry, ok := value.(map[string]any)
		if !ok || len(entry) != 2 {
			return Archive{}, ErrInvalidArchive
		}
		path, pathOK := entry["path"].(string)
		data, dataOK := entry["data"].(map[string]any)
		if !pathOK || !dataOK {
			return Archive{}, ErrInvalidArchive
		}
		archive.Entries = append(archive.Entries, ArchiveEntry{Path: path, Data: data})
	}
	return ValidateArchive(archive)
}

// ValidateArchive returns sorted, detached data. It also validates callers that
// construct an Archive directly instead of decoding an input file.
func ValidateArchive(archive Archive) (Archive, error) {
	if archive.Format != "secretwright-kv" || archive.Version != 1 || archive.Root == "" || !strings.HasPrefix(archive.Root, "/") {
		return Archive{}, ErrInvalidArchive
	}
	root, err := ResolvePath("/", archive.Root)
	if err != nil || root != archive.Root || len(archive.Entries) > MaxTreeEntries {
		return Archive{}, ErrInvalidArchive
	}
	normalized := Archive{
		Format:  archive.Format,
		Version: archive.Version,
		Root:    archive.Root,
		Entries: make([]ArchiveEntry, 0, len(archive.Entries)),
	}
	seen := make(map[string]struct{}, len(archive.Entries))
	dataBytes := 0
	for _, entry := range archive.Entries {
		if !validArchiveKey(entry.Path) {
			return Archive{}, ErrInvalidArchive
		}
		if _, duplicate := seen[entry.Path]; duplicate {
			return Archive{}, ErrInvalidArchive
		}
		seen[entry.Path] = struct{}{}
		data, err := normalizeJSONObject(entry.Data)
		if err != nil {
			return Archive{}, ErrInvalidArchive
		}
		encoded, err := json.Marshal(data)
		if err != nil || len(encoded) > MaxTreeDataBytes-dataBytes {
			return Archive{}, ErrInvalidArchive
		}
		dataBytes += len(encoded)
		normalized.Entries = append(normalized.Entries, ArchiveEntry{Path: entry.Path, Data: data})
	}
	sort.Slice(normalized.Entries, func(i, j int) bool {
		return normalized.Entries[i].Path < normalized.Entries[j].Path
	})
	encoded, err := json.Marshal(normalized)
	if err != nil || len(encoded) >= MaxArchiveBytes {
		// Reserve the final newline written by EncodeArchive.
		return Archive{}, ErrInvalidArchive
	}
	return normalized, nil
}

func validArchiveKey(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || !validLogicalText(value) {
		return false
	}
	segments := strings.Split(value, "/")
	if len(segments) > MaxTreeDepth {
		return false
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// EncodeArchive writes only after validating and normalizing every entry. A
// failed writer never contributes its arbitrary error text to the diagnostic.
func EncodeArchive(output io.Writer, archive Archive) error {
	normalized, err := ValidateArchive(archive)
	if err != nil {
		return err
	}
	body, err := json.Marshal(normalized)
	if err != nil {
		return ErrInvalidArchive
	}
	body = append(body, '\n')
	if output == nil {
		return errArchiveWrite
	}
	n, err := output.Write(body)
	if err != nil || n != len(body) {
		return errArchiveWrite
	}
	return nil
}

// DecodeReplaceRule never accepts credentials or values from argv or the
// command stream. Its caller supplies an explicitly opened input file.
func DecodeReplaceRule(input io.Reader) (map[string]any, map[string]any, error) {
	body, err := readBoundedJSON(input, maxTreeSecretBytes)
	if err != nil {
		return nil, nil, errInvalidReplaceRule
	}
	value, err := decodeStrictJSON(body)
	if err != nil {
		return nil, nil, errInvalidReplaceRule
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 2 {
		return nil, nil, errInvalidReplaceRule
	}
	match, matchOK := object["match"].(map[string]any)
	replacement, replacementOK := object["replacement"].(map[string]any)
	if !matchOK || !replacementOK {
		return nil, nil, errInvalidReplaceRule
	}
	match, err = normalizeJSONObject(match)
	if err != nil {
		return nil, nil, errInvalidReplaceRule
	}
	replacement, err = normalizeJSONObject(replacement)
	if err != nil {
		return nil, nil, errInvalidReplaceRule
	}
	return match, replacement, nil
}

// normalizeJSONObject preserves JSON numbers and detaches arbitrary Go values
// before the same object is compared, validated, or sent to Vault.
func normalizeJSONObject(data map[string]any) (map[string]any, error) {
	if len(data) == 0 {
		return nil, ErrInvalidData
	}
	body, err := json.Marshal(data)
	if err != nil || len(body) > maxTreeSecretBytes {
		return nil, ErrInvalidData
	}
	value, err := decodeStrictJSON(body)
	if err != nil {
		return nil, ErrInvalidData
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) == 0 {
		return nil, ErrInvalidData
	}
	return object, nil
}

func readBoundedJSON(input io.Reader, limit int) ([]byte, error) {
	if input == nil {
		return nil, errStrictJSON
	}
	body, err := io.ReadAll(io.LimitReader(input, int64(limit)+1))
	if err != nil || len(body) > limit || !utf8.Valid(body) {
		return nil, errStrictJSON
	}
	return body, nil
}

// A token walk rejects duplicate decoded member names before a map can hide
// them. This applies to nested secret data as well as archive/rule metadata.
func decodeStrictJSON(body []byte) (any, error) {
	if !utf8.Valid(body) {
		return nil, errStrictJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	value, err := readStrictJSONValue(decoder, 0)
	if err != nil {
		return nil, errStrictJSON
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errStrictJSON
	}
	return value, nil
}

func readStrictJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 10000 {
		return nil, errStrictJSON
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, errStrictJSON
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				member, err := decoder.Token()
				if err != nil {
					return nil, errStrictJSON
				}
				name, ok := member.(string)
				if !ok {
					return nil, errStrictJSON
				}
				if _, duplicate := object[name]; duplicate {
					return nil, errStrictJSON
				}
				child, err := readStrictJSONValue(decoder, depth+1)
				if err != nil {
					return nil, errStrictJSON
				}
				object[name] = child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errStrictJSON
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				child, err := readStrictJSONValue(decoder, depth+1)
				if err != nil {
					return nil, errStrictJSON
				}
				array = append(array, child)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errStrictJSON
			}
			return array, nil
		default:
			return nil, errStrictJSON
		}
	case nil, bool, string, json.Number:
		return value, nil
	default:
		return nil, errStrictJSON
	}
}
