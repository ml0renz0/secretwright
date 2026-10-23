package vault_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/vault"
)

func archiveDocument(entries string) string {
	return "{\"format\":\"secretwright-kv\",\"version\":1,\"root\":\"/legacy/app\",\"entries\":" + entries + "}"
}

func TestArchiveRoundTripPreservesRelativeKeysAndExactNumbers(t *testing.T) {
	source := archiveDocument("[{\"path\":\"foo/bar\",\"data\":{\"value\":\"fixture-secret-value\"}},{\"path\":\"foo\",\"data\":{\"n\":9007199254740993123456789}}]")
	archive, err := vault.DecodeArchive(strings.NewReader(source))
	if err != nil {
		t.Fatalf("decode current-value archive: %v", err)
	}
	if len(archive.Entries) != 2 || archive.Entries[0].Path != "foo" || archive.Entries[1].Path != "foo/bar" || archive.Entries[0].Data["n"] != json.Number("9007199254740993123456789") {
		t.Fatal("archive changed exact numbers or rejected a leaf beside its subtree")
	}
	var encoded bytes.Buffer
	if err := vault.EncodeArchive(&encoded, archive); err != nil {
		t.Fatalf("encode bounded archive: %v", err)
	}
	roundTrip, err := vault.DecodeArchive(&encoded)
	if err != nil || !reflect.DeepEqual(roundTrip, archive) {
		t.Error("archive could not be restored from its own serialized representation")
	}
}

func TestArchiveRejectsAmbiguousSchemaPathsAndDocuments(t *testing.T) {
	valid := archiveDocument("[{\"path\":\"foo\",\"data\":{\"value\":\"fixture-secret-value\"}}]")
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "unknown format", body: strings.Replace(valid, "secretwright-kv", "other-format", 1)},
		{name: "unknown version", body: strings.Replace(valid, "\"version\":1", "\"version\":2", 1)},
		{name: "unknown root field", body: strings.Replace(valid, "\"version\":1", "\"version\":1,\"token\":\"private-secret-marker\"", 1)},
		{name: "unknown entry field", body: archiveDocument("[{\"path\":\"foo\",\"data\":{\"value\":true},\"mount\":\"other\"}]")},
		{name: "relative root", body: strings.Replace(valid, "/legacy/app", "legacy/app", 1)},
		{name: "noncanonical root", body: strings.Replace(valid, "/legacy/app", "/legacy/./app", 1)},
		{name: "absolute entry", body: archiveDocument("[{\"path\":\"/other/app\",\"data\":{\"x\":true}}]")},
		{name: "parent escape", body: archiveDocument("[{\"path\":\"../private\",\"data\":{\"x\":true}}]")},
		{name: "embedded parent", body: archiveDocument("[{\"path\":\"foo/../bar\",\"data\":{\"x\":true}}]")},
		{name: "duplicate slash", body: archiveDocument("[{\"path\":\"foo//bar\",\"data\":{\"x\":true}}]")},
		{name: "directory instead of key", body: archiveDocument("[{\"path\":\"foo/\",\"data\":{\"x\":true}}]")},
		{name: "URL encoded key", body: archiveDocument("[{\"path\":\"foo%2fbar\",\"data\":{\"x\":true}}]")},
		{name: "empty key", body: archiveDocument("[{\"path\":\"\",\"data\":{\"x\":true}}]")},
		{name: "duplicate exact key", body: archiveDocument("[{\"path\":\"foo\",\"data\":{\"x\":true}},{\"path\":\"foo\",\"data\":{\"x\":false}}]")},
		{name: "duplicate archive member", body: strings.Replace(valid, "\"version\":1", "\"version\":1,\"version\":1", 1)},
		{name: "duplicate nested member", body: archiveDocument("[{\"path\":\"foo\",\"data\":{\"x\":true,\"x\":false}}]")},
		{name: "escaped duplicate nested member", body: archiveDocument("[{\"path\":\"foo\",\"data\":{\"x\":true,\"\\u0078\":false}}]")},
		{name: "empty object", body: archiveDocument("[{\"path\":\"foo\",\"data\":{}}]")},
		{name: "null object", body: archiveDocument("[{\"path\":\"foo\",\"data\":null}]")},
		{name: "array values", body: archiveDocument("[{\"path\":\"foo\",\"data\":[1]}]")},
		{name: "null entries", body: archiveDocument("null")},
		{name: "missing entries", body: "{\"format\":\"secretwright-kv\",\"version\":1,\"root\":\"/legacy/app\"}"},
		{name: "second document", body: valid + "\n" + valid},
		{name: "malformed private input", body: "{\"private-secret-marker\":"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := vault.DecodeArchive(strings.NewReader(test.body))
			if !errors.Is(err, vault.ErrInvalidArchive) {
				t.Errorf("unsafe archive error = %v, want invalid archive", err)
			}
			if err != nil && (strings.Contains(err.Error(), "fixture-secret-value") || strings.Contains(err.Error(), "private-secret-marker")) {
				t.Error("archive validation echoed private input")
			}
		})
	}
}

func TestArchiveValidationDetachesDataAndAllowsAnEmptySnapshot(t *testing.T) {
	original := vault.Archive{
		Format:  "secretwright-kv",
		Version: 1,
		Root:    "/secret/app",
		Entries: []vault.ArchiveEntry{
			{Path: "z", Data: map[string]any{"nested": map[string]any{"value": "fixture-secret-value"}}},
			{Path: "a", Data: map[string]any{"n": json.Number("1.00")}},
		},
	}
	normalized, err := vault.ValidateArchive(original)
	if err != nil {
		t.Fatalf("validate detached archive: %v", err)
	}
	original.Entries[0].Data["nested"].(map[string]any)["value"] = "changed-after-validation"
	if normalized.Entries[0].Path != "a" || normalized.Entries[1].Data["nested"].(map[string]any)["value"] != "fixture-secret-value" {
		t.Error("validated archive retained mutable caller data or failed deterministic ordering")
	}
	empty, err := vault.DecodeArchive(strings.NewReader(archiveDocument("[]")))
	if err != nil || empty.Entries == nil || len(empty.Entries) != 0 {
		t.Error("an explicitly empty snapshot was confused with missing archive entries")
	}
}

type privateArchiveWriter struct {
	short bool
}

func (writer privateArchiveWriter) Write(value []byte) (int, error) {
	if writer.short {
		return len(value) - 1, nil
	}
	return 0, errors.New("private-writer-marker")
}

func TestArchiveCodecBoundsInputAndSurfacesSafeWriteFailures(t *testing.T) {
	t.Run("bounded archive input", func(t *testing.T) {
		body := io.MultiReader(strings.NewReader(strings.Repeat(" ", vault.MaxArchiveBytes+1)), strings.NewReader(archiveDocument("[]")))
		if _, err := vault.DecodeArchive(body); !errors.Is(err, vault.ErrInvalidArchive) {
			t.Error("oversized archive was accepted")
		}
	})
	t.Run("entry count", func(t *testing.T) {
		entries := make([]vault.ArchiveEntry, vault.MaxTreeEntries+1)
		for i := range entries {
			entries[i] = vault.ArchiveEntry{Path: fmt.Sprintf("key-%05d", i), Data: map[string]any{"value": true}}
		}
		archive := vault.Archive{Format: "secretwright-kv", Version: 1, Root: "/secret", Entries: entries}
		if _, err := vault.ValidateArchive(archive); !errors.Is(err, vault.ErrInvalidArchive) {
			t.Error("archive entry limit was not enforced")
		}
	})
	t.Run("depth", func(t *testing.T) {
		path := strings.Repeat("next/", vault.MaxTreeDepth) + "key"
		archive := vault.Archive{Format: "secretwright-kv", Version: 1, Root: "/secret", Entries: []vault.ArchiveEntry{{Path: path, Data: map[string]any{"value": true}}}}
		if _, err := vault.ValidateArchive(archive); !errors.Is(err, vault.ErrInvalidArchive) {
			t.Error("archive paths escaped the recursive depth limit")
		}
	})
	for _, short := range []bool{false, true} {
		archive := vault.Archive{Format: "secretwright-kv", Version: 1, Root: "/secret", Entries: []vault.ArchiveEntry{{Path: "item", Data: map[string]any{"value": true}}}}
		err := vault.EncodeArchive(privateArchiveWriter{short: short}, archive)
		if err == nil || strings.Contains(err.Error(), "private-writer-marker") {
			t.Error("archive output ignored a short/failed write or exposed its private error")
		}
	}
}

func TestReplaceRuleIsStrictBoundedAndKeepsNumericPrecision(t *testing.T) {
	source := "{\"match\":{\"n\":9007199254740993123456789},\"replacement\":{\"n\":1.0}}"
	match, replacement, err := vault.DecodeReplaceRule(strings.NewReader(source))
	if err != nil || match["n"] != json.Number("9007199254740993123456789") || replacement["n"] != json.Number("1.0") {
		t.Error("replacement rule lost an exact JSON number")
	}
	for _, body := range []string{
		"{}",
		"{\"match\":{},\"replacement\":{\"x\":true}}",
		"{\"match\":{\"x\":true},\"replacement\":null}",
		"{\"match\":{\"x\":true},\"replacement\":{\"x\":false},\"force\":true}",
		"{\"match\":{\"x\":true,\"x\":false},\"replacement\":{\"x\":false}}",
		"{\"match\":{\"x\":true},\"match\":{\"x\":false},\"replacement\":{\"x\":false}}",
		source + "\n{}",
		strings.Repeat(" ", (1<<20)+1) + source,
		"{\"private-secret-marker\":",
	} {
		_, _, err := vault.DecodeReplaceRule(strings.NewReader(body))
		if err == nil || strings.Contains(err.Error(), "private-secret-marker") {
			t.Error("replacement rule accepted ambiguous input or exposed its data")
		}
	}
}
