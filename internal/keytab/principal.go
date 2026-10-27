package keytab

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

func validPrincipalString(value string) bool {
	return len(value) > 0 && len(value) <= MaxStringBytes && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func escapedPrincipalString(value string) string {
	var result strings.Builder
	for _, character := range value {
		if character == '/' || character == '@' || character == '\\' {
			result.WriteByte('\\')
		}
		result.WriteRune(character)
	}
	return result.String()
}

// CanonicalPrincipal is an injective display encoding, not a normalizer for
// Kerberos identities. Realm and component case remain significant.
func CanonicalPrincipal(realm string, components []string) (string, error) {
	if !validPrincipalString(realm) || len(components) == 0 || len(components) > MaxComponents {
		return "", ErrInvalidInput
	}
	parts := make([]string, len(components))
	length := len(escapedPrincipalString(realm)) + 1
	for index, component := range components {
		if !validPrincipalString(component) {
			return "", ErrInvalidInput
		}
		parts[index] = escapedPrincipalString(component)
		length += len(parts[index])
		if index != 0 {
			length++
		}
		if length > MaxPrincipalBytes {
			return "", ErrInvalidInput
		}
	}
	return strings.Join(parts, "/") + "@" + escapedPrincipalString(realm), nil
}

func samePrincipal(first, second PrincipalSpec) bool {
	if first.Realm != second.Realm || len(first.Components) != len(second.Components) {
		return false
	}
	for index := range first.Components {
		if first.Components[index] != second.Components[index] {
			return false
		}
	}
	return true
}
