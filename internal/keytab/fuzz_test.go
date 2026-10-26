package keytab_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/keytab"
)

// These fixtures are independent of the core unit-test builders so fuzzing can
// exercise both valid and malformed binary records without external tools.
func keytabFuzzCounted(body []byte, value string) []byte {
	body = binary.BigEndian.AppendUint16(body, uint16(len(value)))
	return append(body, value...)
}

func keytabFuzzRecord(key []byte, realm string, components []string, enctype uint16) []byte {
	body := binary.BigEndian.AppendUint16(nil, uint16(len(components)))
	body = keytabFuzzCounted(body, realm)
	for _, component := range components {
		body = keytabFuzzCounted(body, component)
	}
	body = binary.BigEndian.AppendUint32(body, 2)
	body = binary.BigEndian.AppendUint32(body, 0xf0123456)
	body = append(body, 3)
	body = binary.BigEndian.AppendUint16(body, enctype)
	body = binary.BigEndian.AppendUint16(body, uint16(len(key)))
	body = append(body, key...)
	body = binary.BigEndian.AppendUint32(body, 259)
	body = append(body, 0xa1, 0xb2)
	record := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
	return append(record, body...)
}

func keytabFuzzFile(key []byte) []byte {
	body := []byte{5, 2}
	return append(body, keytabFuzzRecord(key, "EXAMPLE.TEST", []string{"HTTP", "app.fixture.test"}, 18)...)
}

func keytabFuzzPolicy() keytab.Policy {
	return keytab.Policy{
		APIVersion: "secretwright/keytab/v1",
		Name:       "fuzz",
		Principal: keytab.PrincipalSpec{
			Realm:      "EXAMPLE.TEST",
			Components: []string{"HTTP", "app.fixture.test"},
		},
		MinimumKVNO:      3,
		AllowedEnctypes:  []uint16{17, 18, 19, 20},
		RequiredEnctypes: []uint16{18},
	}
}

func keytabFuzzError(t *testing.T, err error) {
	t.Helper()
	if err != nil && err != keytab.ErrInvalidInput && err != keytab.ErrInvalidPolicy && err != keytab.ErrValidation {
		t.Fatal("keytab operation returned a non-static diagnostic")
	}
}

func keytabFuzzMetadata(t *testing.T, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal("keytab metadata was not JSON encodable")
	}
	var document any
	if json.Unmarshal(body, &document) != nil {
		t.Fatal("keytab metadata was not valid JSON")
	}
	var inspect func(any)
	inspect = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for name, child := range value {
				lower := strings.ToLower(name)
				if lower != "key_length" && (strings.Contains(lower, "key") || strings.Contains(lower, "hash") || strings.Contains(lower, "sha256") || strings.Contains(lower, "base64") || lower == "data" || lower == "raw" || lower == "bytes") {
					t.Fatal("ordinary keytab metadata exposed a secret-bearing or fingerprint field")
				}
				inspect(child)
			}
		case []any:
			for _, child := range value {
				inspect(child)
			}
		}
	}
	inspect(document)
}

func keytabFuzzValidation(t *testing.T, report keytab.ValidationReport, err error) {
	t.Helper()
	keytabFuzzError(t, err)
	keytabFuzzMetadata(t, report)
	if report.AuthenticationChecked {
		t.Fatal("offline validation claimed to authenticate against Kerberos")
	}
	if err == nil && !report.Valid || err != nil && report.Valid {
		t.Fatal("validation success disagreed with its result")
	}
	if err == keytab.ErrValidation {
		switch report.Reason {
		case "duplicate_entry", "principal_missing", "unexpected_principal", "kvno_too_low", "enctype_not_allowed", "required_enctype_missing":
		default:
			t.Fatal("validation returned an unapproved reason")
		}
	}
}

func FuzzKeytab(f *testing.F) {
	key := bytes.Repeat([]byte{0xb7}, 32)
	valid := keytabFuzzFile(key)
	hole := binary.BigEndian.AppendUint32([]byte{5, 2}, 0xfffffff8)
	hole = append(hole, []byte("old-slot")...)
	hole = append(hole, valid[2:]...)
	terminated := append(append([]byte(nil), valid...), make([]byte, 12)...)
	duplicate := append(append([]byte(nil), valid...), valid[2:]...)
	escaped := append([]byte{5, 2}, keytabFuzzRecord(key, "REALM@EXAMPLE", []string{"HTTP/service", "host\\node"}, 18)...)
	unknown := append([]byte{5, 2}, keytabFuzzRecord([]byte{1, 2, 3, 4, 5}, "EXAMPLE.TEST", []string{"user"}, 65000)...)
	legacy := append([]byte{5, 2}, keytabFuzzRecord(bytes.Repeat([]byte{0xc3}, 16), "EXAMPLE.TEST", []string{"user"}, 23)...)
	for _, seed := range [][]byte{
		nil,
		{5, 2},
		{5, 1},
		{5, 2, 0x80, 0, 0, 0},
		{5, 2, 0, 0, 0, 0},
		{5, 2, 0, 0, 0, 0, 1},
		{5, 2, 0, 0, 0},
		valid,
		hole,
		terminated,
		duplicate,
		escaped,
		unknown,
		legacy,
		valid[:len(valid)-1],
		[]byte("private-keytab-fuzz-marker"),
		keytab.Example(),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		// Full 1 MiB and record-count limits belong to deterministic unit tests.
		// This cap leaves the CI budget for exploring binary structures.
		if len(input) > 16*1024 {
			t.Skip()
		}
		original := append([]byte(nil), input...)
		report, err := keytab.Inspect(bytes.NewReader(input))
		again, againErr := keytab.Inspect(bytes.NewReader(input))
		keytabFuzzError(t, err)
		keytabFuzzError(t, againErr)
		if err != againErr || !reflect.DeepEqual(report, again) {
			t.Fatal("keytab inspection changed for identical bytes")
		}
		if err != nil && !reflect.DeepEqual(report, keytab.Report{}) {
			t.Fatal("failed keytab inspection returned partial metadata")
		}
		if report.AuthenticationChecked {
			t.Fatal("inspection claimed to authenticate against Kerberos")
		}
		keytabFuzzMetadata(t, report)
		if err == nil {
			if report.Version != 2 || report.Holes < 0 || len(report.Entries)+report.Holes > 4096 {
				t.Fatal("inspection returned inconsistent format or record bounds")
			}
			identities := make(map[string]keytab.PrincipalSpec)
			for _, entry := range report.Entries {
				principal, principalErr := keytab.CanonicalPrincipal(entry.Realm, entry.Components)
				if principalErr != nil || principal != entry.Principal || entry.KeyLength <= 0 || entry.Enctype == 0 || entry.Timestamp.Unix() < 0 || entry.Timestamp.Unix() > int64(1<<32-1) || entry.Timestamp.Nanosecond() != 0 {
					t.Fatal("inspection returned invalid principal or entry metadata")
				}
				switch entry.Strength {
				case "strong", "legacy", "unknown":
				default:
					t.Fatal("inspection returned an unknown strength classification")
				}
				identity := keytab.PrincipalSpec{Realm: entry.Realm, Components: entry.Components}
				if prior, exists := identities[principal]; exists && !reflect.DeepEqual(prior, identity) {
					t.Fatal("canonical principal spelling merged distinct identities")
				}
				identities[principal] = identity
			}
		}

		for _, policy := range []keytab.Policy{{}, keytabFuzzPolicy()} {
			before, _ := json.Marshal(policy)
			validation, validationErr := keytab.Validate(bytes.NewReader(input), policy)
			validationAgain, validationAgainErr := keytab.Validate(bytes.NewReader(input), policy)
			keytabFuzzValidation(t, validation, validationErr)
			keytabFuzzValidation(t, validationAgain, validationAgainErr)
			if validationErr != validationAgainErr || validation != validationAgain {
				t.Fatal("keytab validation changed for identical bytes and policy")
			}
			if validationErr == nil && err != nil || validationErr == nil && policy.APIVersion != "" && !validation.PolicyChecked {
				t.Fatal("validation accepted an invalid file or omitted the requested policy check")
			}
			after, _ := json.Marshal(policy)
			if !bytes.Equal(before, after) || policy.APIVersion == "" && validation.PolicyChecked {
				t.Fatal("keytab validation changed its policy or claimed one when absent")
			}
		}

		policy, policyErr := keytab.LoadPolicy(bytes.NewReader(input))
		policyAgain, policyAgainErr := keytab.LoadPolicy(bytes.NewReader(input))
		keytabFuzzError(t, policyErr)
		keytabFuzzError(t, policyAgainErr)
		if policyErr != policyAgainErr || !reflect.DeepEqual(policy, policyAgain) {
			t.Fatal("policy parsing changed for identical bytes")
		}
		if policyErr == nil {
			body, marshalErr := json.Marshal(policy)
			if marshalErr != nil {
				t.Fatal("valid policy could not be JSON encoded")
			}
			roundTrip, roundTripErr := keytab.LoadPolicy(bytes.NewReader(body))
			if roundTripErr != nil || !reflect.DeepEqual(policy, roundTrip) {
				t.Fatal("normalized policy changed across JSON roundtrip")
			}
		}

		// Metadata must not be a verifier of key bytes. Changing only secret
		// material leaves inspection and policy validation exactly unchanged.
		firstKey := sha256.Sum256(input)
		secondKey := firstKey
		for index := range secondKey {
			secondKey[index] ^= 0xff
		}
		firstFile, secondFile := keytabFuzzFile(firstKey[:]), keytabFuzzFile(secondKey[:])
		firstReport, firstErr := keytab.Inspect(bytes.NewReader(firstFile))
		secondReport, secondErr := keytab.Inspect(bytes.NewReader(secondFile))
		if firstErr != nil || secondErr != nil || !reflect.DeepEqual(firstReport, secondReport) {
			t.Fatal("keytab metadata depended on secret key bytes")
		}
		firstValidation, firstValidationErr := keytab.Validate(bytes.NewReader(firstFile), keytabFuzzPolicy())
		secondValidation, secondValidationErr := keytab.Validate(bytes.NewReader(secondFile), keytabFuzzPolicy())
		if firstValidationErr != nil || secondValidationErr != nil || firstValidation != secondValidation {
			t.Fatal("structural policy checks depended on secret key bytes")
		}
		encoded, marshalErr := json.Marshal(firstReport)
		if marshalErr != nil {
			t.Fatal("keytab fixture report could not be encoded")
		}
		keyDigest := sha256.Sum256(firstKey[:])
		fileDigest := sha256.Sum256(firstFile)
		for _, private := range []string{
			base64.StdEncoding.EncodeToString(firstKey[:]),
			hex.EncodeToString(firstKey[:]),
			hex.EncodeToString(keyDigest[:]),
			hex.EncodeToString(fileDigest[:]),
			base64.StdEncoding.EncodeToString(firstFile),
		} {
			if bytes.Contains(encoded, []byte(private)) {
				t.Fatal("keytab metadata exposed secret bytes or a fingerprint")
			}
		}
		if !bytes.Equal(input, original) {
			t.Fatal("keytab operation mutated its input bytes")
		}
	})
}
