package vault

import "errors"

const (
	DefaultConcurrency = 4
	MaxConcurrency     = 16
	MaxTreeEntries     = 10000
	MaxTreeDepth       = 64
	MaxTreeDataBytes   = 32 << 20
	MaxArchiveBytes    = 32 << 20

	maxTreeSecretBytes = 1 << 20
)

var (
	ErrTraversalLimit = errors.New("recursive Vault operation exceeded its entry, depth, or data limit")
	ErrBulkPartial    = errors.New("recursive mutation is incomplete; some changes may have applied; verify reported paths before retrying")
)

// RecursiveOptions bounds concurrent requests while retaining the same logical
// path and mount selection as single-secret operations.
type RecursiveOptions struct {
	KVOptions
	Concurrency int
}

type BulkOptions struct {
	RecursiveOptions
	Force  bool
	DryRun bool
}

// A leaf and directory can share the same path. Directory distinguishes the
// two; the path itself never includes a trailing slash.
type TreeEntry struct {
	Path      string `json:"path"`
	Directory bool   `json:"directory"`
}

type TreeResult struct {
	Root    string      `json:"root"`
	Entries []TreeEntry `json:"entries"`
}

// Bulk reports contain only operation metadata, never planned or stored values.
type BulkItem struct {
	Path        string `json:"path"`
	Destination string `json:"destination,omitempty"`
	Status      string `json:"status"`
	KVVersion   int    `json:"kv_version,omitempty"`
	Version     int    `json:"version,omitempty"`
	Error       string `json:"error,omitempty"`
}

type BulkResult struct {
	Operation   string     `json:"operation"`
	Root        string     `json:"root"`
	Destination string     `json:"destination,omitempty"`
	DryRun      bool       `json:"dry_run"`
	Items       []BulkItem `json:"items"`
}
