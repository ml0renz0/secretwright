package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/vault"
)

var lifecycleName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
var lifecycleHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var lifecycleGeneration = regexp.MustCompile(`^[0-9a-f]{32}$`)
var lifecycleUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func Load(input io.Reader) (Spec, error) {
	value, err := blueprint.DecodeConfiguration(input)
	if err != nil || validateSchema(value) != nil {
		return Spec{}, ErrInvalidLifecycle
	}
	body, err := json.Marshal(value)
	if err != nil {
		return Spec{}, ErrInvalidLifecycle
	}
	var spec Spec
	if json.Unmarshal(body, &spec) != nil {
		return Spec{}, ErrInvalidLifecycle
	}
	return ValidateSpec(spec)
}

func lifecycleMount(value string) bool {
	if value == "" || len(value) > 1024 { return false }
	for _, segment := range strings.Split(value, "/") {
		if !lifecycleName.MatchString(segment) { return false }
	}
	return true
}

func lifecycleSeconds(value string) (int64, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration > 24*time.Hour || duration%time.Second != 0 {
		return 0, ErrInvalidLifecycle
	}
	return int64(duration/time.Second), nil
}

func ValidateSpec(spec Spec) (Spec, error) {
	if spec.APIVersion != APIVersion || !lifecycleName.MatchString(spec.Name) || spec.Provider.Kind != "approle" || !lifecycleName.MatchString(spec.Provider.Role) || !lifecycleMount(spec.Provider.AuthMount) || spec.Consumer.Kind != "token-file" || spec.Verify.Kind != "kv-read" || spec.Verify.KVVersion != 2 || !lifecycleMount(spec.Verify.Mount) {
		return Spec{}, ErrInvalidLifecycle
	}
	file := spec.Consumer.Path
	if file == "" || len(file) > 4096 || !filepath.IsAbs(file) || filepath.Clean(file) != file || file == string(filepath.Separator) || !utf8.ValidString(file) || strings.IndexFunc(file, unicode.IsControl) >= 0 {
		return Spec{}, ErrInvalidLifecycle
	}
	canonical, err := vault.ResolvePath("/", spec.Verify.Path)
	if err != nil || canonical != spec.Verify.Path || !strings.HasPrefix(canonical, "/"+spec.Verify.Mount+"/") {
		return Spec{}, ErrInvalidLifecycle
	}
	below, err := lifecycleSeconds(spec.Policy.RotateBelow)
	if err != nil { return Spec{}, ErrInvalidLifecycle }
	minimum, err := lifecycleSeconds(spec.Policy.MinimumNewTTL)
	if err != nil || minimum < below { return Spec{}, ErrInvalidLifecycle }
	spec.Policy.RotateBelow = (time.Duration(below)*time.Second).String()
	spec.Policy.MinimumNewTTL = (time.Duration(minimum)*time.Second).String()
	return spec, nil
}

func SpecHash(spec Spec) string {
	spec, err := ValidateSpec(spec)
	if err != nil { return "" }
	body, err := json.Marshal(spec)
	if err != nil { return "" }
	return digestBytes(body)
}

func digestBytes(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

func Example() []byte {
	spec := Spec{APIVersion: APIVersion, Name: "payments-api", Provider: ProviderSpec{Kind: "approle", AuthMount: "approle", Role: "payments-api"}, Consumer: ConsumerSpec{Kind: "token-file", Path: "/run/payments/vault-token"}, Verify: VerifySpec{Kind: "kv-read", Mount: "secret", KVVersion: 2, Path: "/secret/payments/health"}, Policy: PolicySpec{RotateBelow: "5m", MinimumNewTTL: "10m"}}
	body, _ := json.MarshalIndent(spec, "", "  ")
	return append(body, '\n')
}
