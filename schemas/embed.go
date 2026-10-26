// Package schemas embeds the same versioned schema published with the source.
package schemas

import _ "embed"

//go:embed blueprint-v1.schema.json
var blueprintV1 []byte

//go:embed architecture-v1.schema.json
var architectureV1 []byte

//go:embed lifecycle-v1.schema.json
var lifecycleV1 []byte

// LifecycleV1 returns a detached copy of the lifecycle policy schema.
func LifecycleV1() []byte { return append([]byte(nil), lifecycleV1...) }

// BlueprintV1 returns a detached copy so callers cannot change validation.
func BlueprintV1() []byte {
	return append([]byte(nil), blueprintV1...)
}

// ArchitectureV1 returns a detached copy of the architecture manifest schema.
func ArchitectureV1() []byte {
	return append([]byte(nil), architectureV1...)
}
