package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

var errKV2Number = fmt.Errorf("%w: KV v2 cannot preserve this JSON number; encode exact values as strings", ErrInvalidData)

// validateKV2Numbers returns the exact JSON object checked for the KV v2
// backend's float64 read conversion. Sending this normalized object also keeps
// custom MarshalJSON implementations from changing values after validation.
func validateKV2Numbers(data map[string]any) (map[string]any, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, ErrInvalidData
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var normalized map[string]any
	if err := decoder.Decode(&normalized); err != nil {
		return nil, ErrInvalidData
	}
	if err := checkKV2Numbers(normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

func checkKV2Numbers(value any) error {
	switch value := value.(type) {
	case map[string]any:
		for _, child := range value {
			if err := checkKV2Numbers(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := checkKV2Numbers(child); err != nil {
				return err
			}
		}
	case json.Number:
		return checkKV2Number(value)
	}
	return nil
}

func checkKV2Number(number json.Number) error {
	text := number.String()
	parsed, err := strconv.ParseFloat(text, 64)
	if math.IsInf(parsed, 0) || math.IsNaN(parsed) {
		return errKV2Number
	}
	if parsed == 0 {
		// Avoid constructing enormous rational denominators for underflowed
		// exponents. An all-zero mantissa is exact at every exponent.
		mantissa := text
		if exponent := strings.IndexAny(text, "eE"); exponent >= 0 {
			mantissa = text[:exponent]
		}
		for _, digit := range mantissa {
			if digit >= '1' && digit <= '9' {
				return errKV2Number
			}
		}
		return nil
	}
	if err != nil {
		return errKV2Number
	}
	canonical, err := json.Marshal(parsed)
	if err != nil {
		return errKV2Number
	}
	original, originalOK := new(big.Rat).SetString(text)
	roundTrip, roundTripOK := new(big.Rat).SetString(string(canonical))
	if !originalOK || !roundTripOK || original.Cmp(roundTrip) != 0 {
		return errKV2Number
	}
	return nil
}
