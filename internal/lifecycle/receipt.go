package lifecycle

import (
	"encoding/json"
	"io"
	"math"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/fileformat"
	"github.com/ml0renz0/secretwright/internal/managedstate"
)

// ValidateReceipt accepts only the bound, non-secret metadata needed to resume
// one generation. Private credential material belongs in fixed-name artifacts.
func ValidateReceipt(r Receipt) error {
	if r.APIVersion != ReceiptVersion || !lifecycleName.MatchString(r.Name) || r.Revision == 0 || r.Revision > math.MaxInt64 || !lifecycleGeneration.MatchString(r.Generation) || !lifecycleHash.MatchString(r.ConfigSHA256) || !lifecycleHash.MatchString(r.RoleIdentity) || !lifecycleHash.MatchString(r.OldDigest) || !lifecycleUUID.MatchString(r.EntityID) || r.Format != fileformat.YAML && r.Format != fileformat.JSON {
		return ErrInvalidLifecycle
	}
	if managedstate.Validate(managedstate.State{APIVersion: managedstate.APIVersion, Blueprint: r.Name, Target: r.Target, Revision: r.Revision, Resources: []managedstate.Record{}}) != nil {
		return ErrInvalidLifecycle
	}
	bundle, candidate := false, false
	switch r.Phase {
	case "prepared", "aborted":
	case "secret_issued", "pending_login":
		bundle = true
	case "candidate_ready", "verified", "pending_publish", "published", "pending_retire", "retired":
		bundle, candidate = true, true
	default:
		return ErrInvalidLifecycle
	}
	if bundle && r.BundleDigest == "" || r.BundleDigest != "" && !lifecycleHash.MatchString(r.BundleDigest) || candidate && r.NewDigest == "" || r.NewDigest != "" && !lifecycleHash.MatchString(r.NewDigest) {
		return ErrInvalidLifecycle
	}
	return nil
}

func receiptKeys(object map[string]any, required, optional []string) bool {
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range required {
		if _, ok := object[key]; !ok {
			return false
		}
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key := range object {
		if !allowed[key] {
			return false
		}
	}
	return true
}

func DecodeReceipt(input io.Reader) (Receipt, error) {
	value, err := blueprint.DecodeConfiguration(input)
	if err != nil {
		return Receipt{}, ErrInvalidLifecycle
	}
	object := value
	if !receiptKeys(object, []string{"api_version", "name", "config_sha256", "target", "revision", "generation", "phase", "role_identity", "old_digest", "entity_id", "format"}, []string{"new_digest", "bundle_digest"}) {
		return Receipt{}, ErrInvalidLifecycle
	}
	for key, value := range object {
		if key != "target" && key != "revision" {
			if _, ok := value.(string); !ok {
				return Receipt{}, ErrInvalidLifecycle
			}
		}
	}
	number, ok := object["revision"].(json.Number)
	if !ok {
		return Receipt{}, ErrInvalidLifecycle
	}
	revision, err := number.Int64()
	if err != nil || revision < 1 {
		return Receipt{}, ErrInvalidLifecycle
	}
	target, ok := object["target"].(map[string]any)
	if !ok || !receiptKeys(target, []string{"address_sha256", "cluster_id", "namespace"}, nil) {
		return Receipt{}, ErrInvalidLifecycle
	}
	for _, value := range target {
		if _, ok := value.(string); !ok {
			return Receipt{}, ErrInvalidLifecycle
		}
	}
	body, err := json.Marshal(object)
	var receipt Receipt
	if err != nil || json.Unmarshal(body, &receipt) != nil || ValidateReceipt(receipt) != nil {
		return Receipt{}, ErrInvalidLifecycle
	}
	return receipt, nil
}
