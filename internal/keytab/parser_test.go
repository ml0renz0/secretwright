package keytab_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/keytab"
)

func ktMetadataPrivate(t *testing.T, report any, source []byte) {
	t.Helper()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal("could not inspect keytab report metadata")
	}
	for _, forbidden := range [][]byte{ktPrivateKeyMarker, []byte(base64.StdEncoding.EncodeToString(source)), []byte(hex.EncodeToString(ktPrivateKeyMarker))} {
		if len(forbidden) != 0 && bytes.Contains(body, forbidden) {
			t.Error("keytab metadata exposed credential bytes or an encoded credential")
		}
	}
}

func TestNativeKeytabInspectionReportsBoundedMetadataWithoutKeys(t *testing.T) {
	record := ktFixtureRecord()
	record.kvno32 = ktNumber(513)
	record.kvno8 = 7
	raw := ktFile(record)
	before := append([]byte(nil), raw...)
	report, err := keytab.Inspect(bytes.NewReader(raw))
	if err != nil || report.Version != 2 || report.AuthenticationChecked || report.Holes != 0 || len(report.Entries) != 1 {
		t.Fatal("native v2 keytab inspection did not return its metadata")
	}
	entry := report.Entries[0]
	if entry.Principal != "HTTP/app.example.test@EXAMPLE.TEST" || entry.Realm != record.realm || !reflect.DeepEqual(entry.Components, record.components) || entry.NameType != 2 || entry.KVNO != 513 || entry.Enctype != 18 || entry.EnctypeName != "aes256-cts-hmac-sha1-96" || entry.Strength != "strong" || entry.KeyLength != 32 || !entry.Timestamp.Equal(time.Unix(int64(record.timestamp), 0)) || entry.Timestamp.Location() != time.UTC {
		t.Error("inspection changed principal, KVNO32, enctype or the unsigned UTC timestamp")
	}
	if !bytes.Equal(raw, before) {
		t.Error("keytab inspection modified its private input bytes")
	}
	entry.Components[0] = "changed"
	again, err := keytab.Inspect(bytes.NewReader(raw))
	if err != nil || again.Entries[0].Components[0] != "HTTP" {
		t.Error("caller mutation changed a later keytab inspection")
	}
	ktMetadataPrivate(t, report, raw)
}

func TestKeytabKVNOFallbackPaddingHolesAndEndMarkersFollowMITV2(t *testing.T) {
	for _, test := range []struct {
		name    string
		vno32   *uint32
		padding []byte
		want    uint32
	}{
		{name: "old eight bit entry", want: 7},
		{name: "one byte reused slot", padding: []byte{0xff}, want: 7},
		{name: "three bytes reused slot", padding: []byte{1, 2, 3}, want: 7},
		{name: "zero extended fallback", vno32: ktNumber(0), want: 7},
		{name: "extended override", vno32: ktNumber(512), want: 512},
		{name: "full unsigned version", vno32: ktNumber(math.MaxUint32), want: math.MaxUint32},
		{name: "extended with opaque padding", vno32: ktNumber(513), padding: []byte("private-slot-padding"), want: 513},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := ktFixtureRecord()
			record.kvno8, record.kvno32, record.padding = 7, test.vno32, test.padding
			report, err := keytab.Inspect(bytes.NewReader(ktFile(record)))
			if err != nil || len(report.Entries) != 1 || report.Entries[0].KVNO != test.want {
				t.Error("reused record padding or the standard KVNO fallback was misread")
			}
		})
	}
	hole := []byte("private-deleted-keytab-record")
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(-int32(len(hole))))
	raw := append([]byte{5, 2}, prefix[:]...)
	raw = append(raw, hole...)
	raw = append(raw, ktFrame(ktEntry(ktFixtureRecord()))...)
	raw = append(raw, make([]byte, 11)...)
	report, err := keytab.Inspect(bytes.NewReader(raw))
	if err != nil || report.Holes != 1 || len(report.Entries) != 1 || report.AuthenticationChecked {
		t.Error("deleted records or a zero terminator with zero padding were not handled safely")
	}
	encoded, _ := json.Marshal(report)
	if bytes.Contains(encoded, hole) {
		t.Error("a deleted slot leaked into keytab metadata")
	}
	for _, empty := range [][]byte{{5, 2}, {5, 2, 0, 0, 0, 0}} {
		report, err := keytab.Inspect(bytes.NewReader(empty))
		if err != nil || report.Version != 2 || len(report.Entries) != 0 || report.AuthenticationChecked {
			t.Error("a valid empty v2 keytab was rejected or claimed authentication")
		}
	}
}

func TestKeytabKnownLegacyAndUnknownEnctypesKeepTheirStructuralMeaning(t *testing.T) {
	for _, test := range []struct {
		typeID   uint16
		length   int
		strength string
	}{
		{1, 8, "legacy"}, {2, 8, "legacy"}, {3, 8, "legacy"}, {16, 24, "legacy"},
		{17, 16, "strong"}, {18, 32, "strong"}, {19, 16, "strong"}, {20, 32, "strong"},
		{23, 16, "legacy"}, {24, 16, "legacy"}, {25, 16, "strong"}, {26, 32, "strong"},
		{65535, 17, "unknown"},
	} {
		record := ktFixtureRecord()
		record.enctype, record.key = test.typeID, bytes.Repeat([]byte{0xff}, test.length)
		report, err := keytab.Inspect(bytes.NewReader(ktFile(record)))
		if err != nil || len(report.Entries) != 1 || report.Entries[0].Enctype != test.typeID || report.Entries[0].KeyLength != test.length || report.Entries[0].Strength != test.strength || report.Entries[0].EnctypeName == "" {
			t.Error("known or unknown encryption metadata was changed")
		}
		if test.strength == "unknown" {
			if report.Entries[0].EnctypeName != "unknown" {
				t.Error("unknown enctype was assigned an invented recognized name")
			}
			continue
		}
		record.key = record.key[:len(record.key)-1]
		if report, err := keytab.Inspect(bytes.NewReader(ktFile(record))); err != keytab.ErrInvalidInput || !reflect.DeepEqual(report, keytab.Report{}) {
			t.Error("known enctype accepted an incorrect key size or returned partial metadata")
		}
	}
}

func TestKeytabRejectsTruncationInvalidRecordsAndUnsupportedVersionsWithoutEcho(t *testing.T) {
	raw := ktFile(ktFixtureRecord())
	badInputs := [][]byte{
		nil, {}, {5}, {5, 1}, {5, 3}, {2, 5}, {0, 0},
		{5, 2, 0x7f, 0xff, 0xff, 0xff}, {5, 2, 0x80, 0, 0, 0},
		{5, 2, 0xff, 0xff, 0xff, 0xfe, 0},
		append([]byte{5, 2, 0, 0, 0, 0}, ktFrame(ktEntry(ktFixtureRecord()))...),
		append(append([]byte(nil), raw...), 1),
		append([]byte{5, 2}, bytes.Repeat([]byte{0}, keytab.MaxInputBytes)...),
	}
	for size := 3; size < len(raw); size++ {
		badInputs = append(badInputs, append([]byte(nil), raw[:size]...))
	}
	for _, edit := range []func(*ktRecord){
		func(r *ktRecord) { r.components = nil },
		func(r *ktRecord) { r.components = []string{""} },
		func(r *ktRecord) { r.realm = "" },
		func(r *ktRecord) { r.realm = "private-marker\x00realm" },
		func(r *ktRecord) { r.components = []string{string([]byte{0xff})} },
		func(r *ktRecord) { r.components = []string{"private-marker\ncomponent"} },
		func(r *ktRecord) { r.realm = strings.Repeat("r", keytab.MaxStringBytes+1) },
		func(r *ktRecord) { r.components = make([]string, keytab.MaxComponents+1) },
		func(r *ktRecord) { r.enctype = 0 },
		func(r *ktRecord) { r.key = nil },
	} {
		record := ktFixtureRecord()
		edit(&record)
		badInputs = append(badInputs, ktFile(record))
	}
	for _, input := range badInputs {
		report, err := keytab.Inspect(bytes.NewReader(input))
		ktRequireError(t, err, keytab.ErrInvalidInput)
		if !reflect.DeepEqual(report, keytab.Report{}) || strings.Contains(err.Error(), "private-marker") || bytes.Contains([]byte(err.Error()), ktPrivateKeyMarker) {
			t.Error("malformed keytab returned partial metadata or echoed rejected input")
		}
	}
	if _, err := keytab.Inspect(nil); err != keytab.ErrInvalidInput {
		t.Error("nil keytab reader was accepted")
	}
	if _, err := keytab.Inspect(ktFailingReader{}); err != keytab.ErrInvalidInput {
		t.Error("upstream reader error escaped the static keytab diagnostic")
	}
}

type ktFailingReader struct{}

func (ktFailingReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestKeytabRecordLimitCountsDeletedRecordsAsWellAsEntries(t *testing.T) {
	raw := []byte{5, 2}
	for index := 0; index < keytab.MaxRecords; index++ {
		raw = append(raw, 0xff, 0xff, 0xff, 0xff, 0)
	}
	if report, err := keytab.Inspect(bytes.NewReader(raw)); err != nil || report.Holes != keytab.MaxRecords {
		t.Fatal("bounded valid deleted records were rejected")
	}
	raw = append(raw, 0xff, 0xff, 0xff, 0xff, 0)
	if report, err := keytab.Inspect(bytes.NewReader(raw)); err != keytab.ErrInvalidInput || !reflect.DeepEqual(report, keytab.Report{}) {
		t.Error("deleted slots bypassed the keytab record limit")
	}
}

func TestPrincipalDisplayIsInjectiveEscapedAndCasePreserving(t *testing.T) {
	for _, test := range []struct {
		realm      string
		components []string
		want       string
	}{
		{"EXAMPLE.TEST", []string{"HTTP", "App.Example.test"}, "HTTP/App.Example.test@EXAMPLE.TEST"},
		{"REALM@EXAMPLE", []string{"HTTP", "host/service"}, `HTTP/host\/service@REALM\@EXAMPLE`},
		{`R\X`, []string{`a\b`, "c@d/e"}, `a\\b/c\@d\/e@R\\X`},
		{"EXAMPLE.TEST", []string{"HTTP", "my host"}, "HTTP/my host@EXAMPLE.TEST"},
	} {
		got, err := keytab.CanonicalPrincipal(test.realm, test.components)
		if err != nil || got != test.want {
			t.Error("canonical principal lost case, literal separators or spaces")
		}
	}
	first, _ := keytab.CanonicalPrincipal("REALM", []string{"a/b", "c"})
	second, _ := keytab.CanonicalPrincipal("REALM", []string{"a", "b/c"})
	if first == second {
		t.Error("different structured principals acquired the same display identity")
	}
	for _, principal := range []keytab.PrincipalSpec{
		{Realm: "", Components: []string{"app"}},
		{Realm: "REALM", Components: nil},
		{Realm: "REALM", Components: []string{""}},
		{Realm: "REALM\x00", Components: []string{"app"}},
		{Realm: "REALM", Components: []string{"app\tservice"}},
		{Realm: string([]byte{0xff}), Components: []string{"app"}},
		{Realm: "REALM", Components: []string{strings.Repeat("x", keytab.MaxStringBytes+1)}},
		{Realm: "REALM", Components: []string{strings.Repeat("/", 1024), strings.Repeat("/", 1024)}},
	} {
		if value, err := keytab.CanonicalPrincipal(principal.Realm, principal.Components); err != keytab.ErrInvalidInput || value != "" {
			t.Error("invalid principal produced a display value or a non-static error")
		}
	}
}

func TestNativeEntriesKeepEscapedPrincipalIdentitiesDistinct(t *testing.T) {
	first, second := ktFixtureRecord(), ktFixtureRecord()
	first.realm, second.realm = "R@EXAMPLE", "R@EXAMPLE"
	first.components = []string{"a/b", "c"}
	second.components = []string{"a", "b/c"}
	raw := ktFile(first, second)
	report, err := keytab.Inspect(bytes.NewReader(raw))
	if err != nil || len(report.Entries) != 2 || report.Entries[0].Principal == report.Entries[1].Principal || !reflect.DeepEqual(report.Entries[0].Components, first.components) || !reflect.DeepEqual(report.Entries[1].Components, second.components) {
		t.Fatal("binary principal components were flattened into an ambiguous identity")
	}
	if validated, err := keytab.Validate(bytes.NewReader(raw), keytab.Policy{}); err != nil || !validated.Valid {
		t.Error("different structured principals were mistaken for duplicate entries")
	}
}
