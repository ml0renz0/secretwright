package vault

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/hashicorp/vault/api"
)

type plannedSnapshot struct {
	target   kvTarget
	data     map[string]any
	revision int
}

func normalizeRecursiveOptions(opts RecursiveOptions) (RecursiveOptions, error) {
	if opts.Concurrency == 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.Concurrency < 1 || opts.Concurrency > MaxConcurrency {
		return RecursiveOptions{}, ErrInvalidPath
	}
	cwd, err := ResolvePath(opts.CWD, "")
	if err != nil {
		return RecursiveOptions{}, err
	}
	opts.CWD = cwd
	if opts.Mount == "" && opts.Version == 0 {
		return opts, nil
	}
	if opts.Mount == "" || (opts.Version != 1 && opts.Version != 2) {
		return RecursiveOptions{}, ErrInvalidPath
	}
	mount, err := canonicalMount(opts.Mount)
	if err != nil {
		return RecursiveOptions{}, err
	}
	opts.Mount = mount
	return opts, nil
}

// Walk lists names only. A complete, sorted result is returned only after every
// discovered directory has been listed successfully within the operation limits.
func (c *Client) Walk(ctx context.Context, token, target string, opts RecursiveOptions) (TreeResult, error) {
	opts, err := normalizeRecursiveOptions(opts)
	if err != nil {
		return TreeResult{}, err
	}
	root, explicit, err := prepareKVPath(target, opts.KVOptions)
	if err != nil {
		return TreeResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return TreeResult{}, err
	}
	defer client.SetToken("")
	return walkTree(ctx, client, root, explicit, opts.Concurrency)
}

type walkDirectory struct {
	path  string
	depth int
}

func walkTree(ctx context.Context, client *api.Client, root string, explicit *Mount, concurrency int) (TreeResult, error) {
	entries := make([]TreeEntry, 0)
	level := []walkDirectory{{path: root}}
	var countMu sync.Mutex
	count := 0
	for len(level) != 0 {
		children := make([][]string, len(level))
		err := runTreeTasks(ctx, concurrency, len(level), func(taskCtx context.Context, index int) error {
			names, err := listTreeChildren(taskCtx, client, level[index].path, explicit)
			if err != nil {
				return err
			}
			if len(names) != 0 && level[index].depth >= MaxTreeDepth {
				return ErrTraversalLimit
			}
			countMu.Lock()
			count += len(names)
			overLimit := count > MaxTreeEntries
			countMu.Unlock()
			if overLimit {
				return ErrTraversalLimit
			}
			children[index] = names
			return nil
		})
		if err != nil {
			return TreeResult{}, err
		}
		next := make([]walkDirectory, 0)
		for index, names := range children {
			for _, name := range names {
				logical := path.Join(level[index].path, strings.TrimSuffix(name, "/"))
				directory := strings.HasSuffix(name, "/")
				entries = append(entries, TreeEntry{Path: logical, Directory: directory})
				if directory {
					next = append(next, walkDirectory{path: logical, depth: level[index].depth + 1})
				}
			}
		}
		level = next
	}
	if err := ctx.Err(); err != nil {
		return TreeResult{}, err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Path == entries[j].Path {
			return !entries[i].Directory && entries[j].Directory
		}
		return entries[i].Path < entries[j].Path
	})
	return TreeResult{Root: root, Entries: entries}, nil
}

// Vault returns 404 when a real mount has no keys. Discovery can establish
// that this directory exists independently of LIST, but an explicit mount
// selection alone is not proof. Never extend this exception to subdirectories.
func listTreeChildren(ctx context.Context, client *api.Client, logical string, explicit *Mount) ([]string, error) {
	names, err := listKVChildren(ctx, client, logical, explicit)
	if !errors.Is(err, ErrNotFound) || explicit != nil || logical == "/" {
		return names, err
	}
	mount, mountErr := selectMount(ctx, client, logical, nil)
	if mountErr == nil && logical == "/"+strings.TrimSuffix(mount.Path, "/") {
		return []string{}, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, err
}

// runTreeTasks stops scheduling work after failure and joins every active
// request before its caller can clear the operation-owned client's token.
func runTreeTasks(ctx context.Context, concurrency, count int, execute func(context.Context, int) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	var workers sync.WaitGroup
	var errorMu sync.Mutex
	var firstError error
	for worker := 0; worker < concurrency && worker < count; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if taskCtx.Err() != nil {
					return
				}
				if err := execute(taskCtx, index); err != nil {
					errorMu.Lock()
					if firstError == nil {
						firstError = err
						cancel()
					}
					errorMu.Unlock()
					return
				}
			}
		}()
	}
dispatch:
	for index := 0; index < count; index++ {
		select {
		case <-taskCtx.Done():
			break dispatch
		case jobs <- index:
		}
	}
	close(jobs)
	workers.Wait()
	if firstError != nil {
		return firstError
	}
	return ctx.Err()
}

// treeSnapshots treats the root as a directory: a same-name leaf at the root
// itself is excluded. Every discovered leaf must have a readable current value.
func (c *Client) treeSnapshots(ctx context.Context, token, target string, opts RecursiveOptions) (string, []plannedSnapshot, error) {
	opts, err := normalizeRecursiveOptions(opts)
	if err != nil {
		return "", nil, err
	}
	root, explicit, err := prepareKVPath(target, opts.KVOptions)
	if err != nil {
		return "", nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return "", nil, err
	}
	defer client.SetToken("")
	tree, err := walkTree(ctx, client, root, explicit, opts.Concurrency)
	if err != nil {
		return "", nil, err
	}
	paths := make([]string, 0, len(tree.Entries))
	for _, entry := range tree.Entries {
		if !entry.Directory {
			paths = append(paths, entry.Path)
		}
	}
	snapshots := make([]plannedSnapshot, len(paths))
	var dataMu sync.Mutex
	totalBytes := 0
	err = runTreeTasks(ctx, opts.Concurrency, len(paths), func(taskCtx context.Context, index int) error {
		selected, err := resolveKVTarget(taskCtx, client, paths[index], opts.KVOptions)
		if err != nil {
			return err
		}
		data, revision, err := readSnapshot(taskCtx, client, selected, 0, true)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(data)
		if err != nil || len(data) == 0 {
			return ErrInvalidData
		}
		if len(encoded) > maxTreeSecretBytes {
			return ErrTraversalLimit
		}
		normalized, err := normalizeJSONObject(data)
		if err != nil {
			return err
		}
		dataMu.Lock()
		totalBytes += len(encoded)
		overLimit := totalBytes > MaxTreeDataBytes
		dataMu.Unlock()
		if overLimit {
			return ErrTraversalLimit
		}
		snapshots[index] = plannedSnapshot{target: selected, data: normalized, revision: revision}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return root, snapshots, nil
}

// Find compares complete objects, including nested values, without returning
// any stored values or coercing numbers through float64.
func (c *Client) Find(ctx context.Context, token, target string, match map[string]any, opts RecursiveOptions) ([]string, error) {
	match, err := normalizeJSONObject(match)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	_, snapshots, err := c.treeSnapshots(ctx, token, target, opts)
	if err != nil {
		return nil, err
	}
	matches := make([]string, 0)
	for _, snapshot := range snapshots {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// Both operands are already detached, validated JSON objects. Reuse
		// them rather than re-encoding a potentially large match per key.
		if equalJSONValues(match, snapshot.data) {
			matches = append(matches, snapshot.target.logical)
		}
	}
	return matches, nil
}

// Backup returns an in-memory archive only after reading the entire directory.
// Publishing a private no-clobber file belongs to the command interface.
func (c *Client) Backup(ctx context.Context, token, target string, opts RecursiveOptions) (Archive, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	root, snapshots, err := c.treeSnapshots(ctx, token, target, opts)
	if err != nil {
		return Archive{}, err
	}
	entries := make([]ArchiveEntry, 0, len(snapshots))
	for _, snapshot := range snapshots {
		entries = append(entries, ArchiveEntry{
			Path: strings.TrimPrefix(snapshot.target.logical, strings.TrimSuffix(root, "/")+"/"),
			Data: snapshot.data,
		})
	}
	archive, err := ValidateArchive(Archive{Format: "secretwright-kv", Version: 1, Root: root, Entries: entries})
	if err != nil {
		return Archive{}, err
	}
	if err := ctx.Err(); err != nil {
		return Archive{}, err
	}
	return archive, nil
}
