package architecture

import (
	"encoding/json"
	"io"
	"regexp"
	"sort"

	"github.com/ml0renz0/secretwright/internal/blueprint"
)

var (
	manifestLabel = regexp.MustCompile(`^[a-z][a-z0-9-]{0,23}$`)
	manifestMount = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}(/[a-z0-9][a-z0-9_.-]{0,127})*$`)
)

func parseManifest(input io.Reader) (Manifest, error) {
	value, err := blueprint.DecodeConfiguration(input)
	if err != nil || validateSchema(value) != nil {
		return Manifest{}, ErrInvalidTemplate
	}
	body, err := json.Marshal(value)
	if err != nil {
		return Manifest{}, ErrInvalidTemplate
	}
	var manifest Manifest
	if json.Unmarshal(body, &manifest) != nil || !manifestLabel.MatchString(manifest.Name) {
		return Manifest{}, ErrInvalidTemplate
	}
	identifiers := make(map[string]bool, len(manifest.Instances))
	for index := range manifest.Instances {
		instance := &manifest.Instances[index]
		if identifiers[instance.ID] || !manifestLabel.MatchString(instance.ID) || !validManifestMount(instance.Mount) {
			return Manifest{}, ErrInvalidTemplate
		}
		identifiers[instance.ID] = true
		if instance.Access == "" {
			instance.Access = "read"
		}
		if instance.Template != "single-user" && instance.Template != "multi-user" && instance.AuthMount == "" {
			instance.AuthMount = "approle"
		}
		if instance.AuthMount != "" && !validManifestMount(instance.AuthMount) {
			return Manifest{}, ErrInvalidTemplate
		}
		for _, labels := range [][]string{instance.Users, instance.Applications, instance.Environments, instance.Tenants} {
			sort.Strings(labels)
			for _, label := range labels {
				if !manifestLabel.MatchString(label) {
					return Manifest{}, ErrInvalidTemplate
				}
			}
			for offset := 1; offset < len(labels); offset++ {
				if labels[offset] == labels[offset-1] {
					return Manifest{}, ErrInvalidTemplate
				}
			}
		}
	}
	sort.Slice(manifest.Instances, func(first, second int) bool {
		return manifest.Instances[first].ID < manifest.Instances[second].ID
	})
	return manifest, nil
}

func validManifestMount(value string) bool {
	return len(value) <= 1024 && manifestMount.MatchString(value)
}
