package vault

import (
	"encoding/json"
	"math/big"
	"strings"
)

// equalJSONObjects compares JSON values structurally. Numbers use their exact
// decimal value: 1, 1.0, and 1e0 compare equally without a float64 conversion.
func equalJSONObjects(a, b map[string]any) (bool, error) {
	left, err := normalizeJSONObject(a)
	if err != nil {
		return false, err
	}
	right, err := normalizeJSONObject(b)
	if err != nil {
		return false, err
	}
	return equalJSONValues(left, right), nil
}

func equalJSONValues(a, b any) bool {
	switch left := a.(type) {
	case nil:
		return b == nil
	case bool:
		right, ok := b.(bool)
		return ok && left == right
	case string:
		right, ok := b.(string)
		return ok && left == right
	case json.Number:
		right, ok := b.(json.Number)
		if !ok {
			return false
		}
		leftSign, leftDigits, leftExponent := canonicalJSONNumber(left)
		rightSign, rightDigits, rightExponent := canonicalJSONNumber(right)
		return leftSign == rightSign && leftDigits == rightDigits && leftExponent == rightExponent
	case []any:
		right, ok := b.([]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for i := range left {
			if !equalJSONValues(left[i], right[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		right, ok := b.(map[string]any)
		if !ok || len(left) != len(right) {
			return false
		}
		for key, value := range left {
			other, present := right[key]
			if !present || !equalJSONValues(value, other) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// Coefficients remain strings. big.Int stores only the decimal exponent, never
// 10^exponent, so even a value such as 1e999999999999999999999 is inexpensive.
// The caller has already validated the token through encoding/json.
func canonicalJSONNumber(number json.Number) (negative bool, digits, exponent string) {
	text := number.String()
	if strings.HasPrefix(text, "-") {
		negative = true
		text = text[1:]
	}
	exponentText := "0"
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		exponentText = text[index+1:]
		text = text[:index]
	}
	fractionalDigits := 0
	if index := strings.IndexByte(text, '.'); index >= 0 {
		fractionalDigits = len(text) - index - 1
		text = text[:index] + text[index+1:]
	}
	digits = strings.TrimLeft(text, "0")
	if digits == "" {
		return false, "0", "0"
	}
	trimmed := strings.TrimRight(digits, "0")
	trailingZeros := len(digits) - len(trimmed)
	digits = trimmed
	var scale big.Int
	scale.SetString(exponentText, 10)
	scale.Add(&scale, big.NewInt(int64(trailingZeros-fractionalDigits)))
	return negative, digits, scale.String()
}
