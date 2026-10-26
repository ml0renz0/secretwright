package pki

import (
	"encoding/json"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ml0renz0/secretwright/internal/configuration"
)

var resourceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func canonicalDNS(value string) (string, bool) {
	if len(value) == 0 || len(value) > 253 {
		return "", false
	}
	for _, character := range value {
		if character > 127 {
			return "", false
		}
	}
	value = strings.ToLower(value)
	for _, label := range strings.Split(value, ".") {
		if !dnsLabel.MatchString(label) {
			return "", false
		}
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return "", false
	}
	return value, true
}

func stringSet(values []string) []string {
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

func normalizeKey(key KeySpec) (KeySpec, error) {
	if key.Type == "" {
		key.Type = "ecdsa"
	}
	switch key.Type {
	case "ecdsa":
		if key.Bits == 0 {
			key.Bits = 256
		}
		if key.Bits != 256 && key.Bits != 384 {
			return KeySpec{}, ErrInvalidInput
		}
	case "rsa":
		if key.Bits != 2048 && key.Bits != 3072 && key.Bits != 4096 {
			return KeySpec{}, ErrInvalidInput
		}
	case "ed25519":
		if key.Bits != 0 {
			return KeySpec{}, ErrInvalidInput
		}
	default:
		return KeySpec{}, ErrInvalidInput
	}
	return key, nil
}

func requestTTL(value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 || duration > 24*time.Hour || duration%time.Second != 0 {
		return 0, ErrInvalidInput
	}
	return duration, nil
}

func ValidateSpec(spec Spec) (Spec, error) {
	if spec.APIVersion != APIVersion || !resourceName.MatchString(spec.Name) || len(spec.DNSNames)+len(spec.IPAddresses) < 1 || len(spec.DNSNames)+len(spec.IPAddresses) > 64 {
		return Spec{}, ErrInvalidInput
	}
	dns := make([]string, 0, len(spec.DNSNames))
	for _, name := range spec.DNSNames {
		canonical, ok := canonicalDNS(name)
		if !ok {
			return Spec{}, ErrInvalidInput
		}
		dns = append(dns, canonical)
	}
	ips := make([]string, 0, len(spec.IPAddresses))
	for _, text := range spec.IPAddresses {
		address, err := netip.ParseAddr(text)
		if err != nil || address.Zone() != "" {
			return Spec{}, ErrInvalidInput
		}
		ips = append(ips, address.Unmap().String())
	}
	spec.DNSNames, spec.IPAddresses = stringSet(dns), stringSet(ips)
	if spec.CommonName != "" {
		common, ok := canonicalDNS(spec.CommonName)
		candidates := spec.DNSNames
		if address, err := netip.ParseAddr(spec.CommonName); err == nil && address.Zone() == "" {
			common, ok, candidates = address.Unmap().String(), true, spec.IPAddresses
		}
		found := false
		for _, name := range candidates {
			found = found || name == common
		}
		if !ok || !found {
			return Spec{}, ErrInvalidInput
		}
		spec.CommonName = common
	}
	duration, err := requestTTL(spec.TTL)
	if err != nil {
		return Spec{}, err
	}
	spec.TTL = duration.String()
	if spec.Usage == "" {
		spec.Usage = "server-auth"
	}
	if spec.Usage != "server-auth" && spec.Usage != "client-auth" {
		return Spec{}, ErrInvalidInput
	}
	spec.Key, err = normalizeKey(spec.Key)
	if err != nil {
		return Spec{}, err
	}
	return spec, nil
}

func Load(input io.Reader) (Spec, error) {
	object, err := configuration.DecodeObject(input)
	if err != nil || validateSchema(object) != nil {
		return Spec{}, ErrInvalidInput
	}
	body, err := json.Marshal(object)
	var spec Spec
	if err != nil || json.Unmarshal(body, &spec) != nil {
		return Spec{}, ErrInvalidInput
	}
	return ValidateSpec(spec)
}

func Example() []byte {
	spec := Spec{APIVersion: APIVersion, Name: "application", CommonName: "app.example.test", DNSNames: []string{"app.example.test"}, IPAddresses: []string{}, TTL: "1h", Usage: "server-auth", Key: KeySpec{Type: "ecdsa", Bits: 256}}
	body, _ := json.MarshalIndent(spec, "", "  ")
	return append(body, '\n')
}
