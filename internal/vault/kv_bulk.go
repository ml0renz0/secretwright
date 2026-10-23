package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/hashicorp/vault/api"
)

type bulkPlanItem struct {
	item      BulkItem
	target    kvTarget
	data      map[string]any
	revision  int
	deletion  bool
	unchanged bool
}

// Replace compares complete JSON objects and conditionally replaces matching
// current snapshots. All reads and output validation finish before any write.
func (c *Client) Replace(ctx context.Context, token, target string, match, replacement map[string]any, opts BulkOptions) (BulkResult, error) {
	var err error
	opts.RecursiveOptions, err = normalizeRecursiveOptions(opts.RecursiveOptions)
	if err != nil {
		return BulkResult{}, err
	}
	match, err = normalizeJSONObject(match)
	if err != nil {
		return BulkResult{}, err
	}
	replacement, err = normalizeJSONObject(replacement)
	if err != nil {
		return BulkResult{}, err
	}
	if _, err := bulkRootPath(target, opts.KVOptions); err != nil {
		return BulkResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return BulkResult{}, err
	}
	defer client.SetToken("")
	root, err := resolveBulkRoot(ctx, client, target, opts.KVOptions)
	if err != nil {
		return BulkResult{}, err
	}
	if root.mount.Version == 1 && !opts.Force {
		return BulkResult{}, ErrUnsupportedOperation
	}
	_, snapshots, err := c.treeSnapshots(ctx, token, root.logical, opts.RecursiveOptions)
	if err != nil {
		return BulkResult{}, err
	}
	plans := make([]bulkPlanItem, 0, len(snapshots))
	outputBytes := 0
	for _, snapshot := range snapshots {
		if !sameBulkMount(root, snapshot.target) {
			return BulkResult{}, ErrInvalidPath
		}
		if !equalJSONValues(snapshot.data, match) {
			continue
		}
		unchanged := equalJSONValues(snapshot.data, replacement)
		data := replacement
		if !unchanged {
			data, err = prepareBulkWrite(snapshot.target, replacement, opts.Force)
			if err != nil {
				return BulkResult{}, err
			}
			if err := addBulkDataBytes(&outputBytes, data); err != nil {
				return BulkResult{}, err
			}
		}
		plans = append(plans, bulkPlanItem{
			item:   BulkItem{Path: snapshot.target.logical, KVVersion: snapshot.target.mount.Version},
			target: snapshot.target, data: data, revision: snapshot.revision, unchanged: unchanged,
		})
	}
	return executeBulk(ctx, client, "replace", root.logical, "", plans, opts)
}

// CopyTree copies directory contents into a disjoint destination. Each KV v2
// destination is create-only; no source deletion or implicit rollback occurs.
func (c *Client) CopyTree(ctx context.Context, token, source, destination string, opts BulkOptions) (BulkResult, error) {
	var err error
	opts.RecursiveOptions, err = normalizeRecursiveOptions(opts.RecursiveOptions)
	if err != nil {
		return BulkResult{}, err
	}
	sourcePath, err := bulkRootPath(source, opts.KVOptions)
	if err != nil {
		return BulkResult{}, err
	}
	destinationPath, err := bulkRootPath(destination, opts.KVOptions)
	if err != nil {
		return BulkResult{}, err
	}
	if overlappingBulkRoots(sourcePath, destinationPath) {
		return BulkResult{}, ErrInvalidPath
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return BulkResult{}, err
	}
	defer client.SetToken("")
	src, err := resolveBulkRoot(ctx, client, sourcePath, opts.KVOptions)
	if err != nil {
		return BulkResult{}, err
	}
	dst, err := resolveBulkRoot(ctx, client, destinationPath, opts.KVOptions)
	if err != nil {
		return BulkResult{}, err
	}
	if dst.mount.Version == 1 && !opts.Force {
		return BulkResult{}, ErrUnsupportedOperation
	}
	_, snapshots, err := c.treeSnapshots(ctx, token, src.logical, opts.RecursiveOptions)
	if err != nil {
		return BulkResult{}, err
	}
	plans := make([]bulkPlanItem, 0, len(snapshots))
	outputBytes := 0
	for _, snapshot := range snapshots {
		if !sameBulkMount(src, snapshot.target) || !strings.HasPrefix(snapshot.target.logical, src.logical+"/") {
			return BulkResult{}, ErrInvalidPath
		}
		relative := strings.TrimPrefix(snapshot.target.logical, src.logical+"/")
		selected, err := resolveKVTarget(ctx, client, dst.logical+"/"+relative, opts.KVOptions)
		if err != nil {
			return BulkResult{}, err
		}
		if !sameBulkMount(dst, selected) {
			return BulkResult{}, ErrInvalidPath
		}
		data, err := prepareBulkWrite(selected, snapshot.data, opts.Force)
		if err != nil {
			return BulkResult{}, err
		}
		if err := addBulkDataBytes(&outputBytes, data); err != nil {
			return BulkResult{}, err
		}
		plans = append(plans, bulkPlanItem{
			item:   BulkItem{Path: snapshot.target.logical, Destination: selected.logical, KVVersion: selected.mount.Version},
			target: selected, data: data,
		})
	}
	return executeBulk(ctx, client, "cptree", src.logical, dst.logical, plans, opts)
}

// RemoveTree deletes only the revisions captured while planning. A newer KV v2
// revision written concurrently remains live, and no metadata is destroyed.
func (c *Client) RemoveTree(ctx context.Context, token, target string, opts BulkOptions) (BulkResult, error) {
	var err error
	opts.RecursiveOptions, err = normalizeRecursiveOptions(opts.RecursiveOptions)
	if err != nil {
		return BulkResult{}, err
	}
	if _, err := bulkRootPath(target, opts.KVOptions); err != nil {
		return BulkResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return BulkResult{}, err
	}
	defer client.SetToken("")
	root, err := resolveBulkRoot(ctx, client, target, opts.KVOptions)
	if err != nil {
		return BulkResult{}, err
	}
	if root.key == "" {
		return BulkResult{}, ErrInvalidPath
	}
	if root.mount.Version == 1 && !opts.Force {
		return BulkResult{}, ErrUnsupportedOperation
	}
	_, snapshots, err := c.treeSnapshots(ctx, token, root.logical, opts.RecursiveOptions)
	if err != nil {
		return BulkResult{}, err
	}
	plans := make([]bulkPlanItem, 0, len(snapshots))
	for _, snapshot := range snapshots {
		if !sameBulkMount(root, snapshot.target) {
			return BulkResult{}, ErrInvalidPath
		}
		plans = append(plans, bulkPlanItem{
			item:   BulkItem{Path: snapshot.target.logical, KVVersion: snapshot.target.mount.Version},
			target: snapshot.target, revision: snapshot.revision, deletion: true,
		})
	}
	return executeBulk(ctx, client, "rmtree", root.logical, "", plans, opts)
}

// Restore validates a detached archive before authenticating or resolving any
// destination. Archive paths select only keys beneath the explicit destination.
func (c *Client) Restore(ctx context.Context, token, destination string, archive Archive, opts BulkOptions) (BulkResult, error) {
	archive, err := ValidateArchive(archive)
	if err != nil {
		return BulkResult{}, err
	}
	opts.RecursiveOptions, err = normalizeRecursiveOptions(opts.RecursiveOptions)
	if err != nil {
		return BulkResult{}, err
	}
	if _, err := bulkRootPath(destination, opts.KVOptions); err != nil {
		return BulkResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	client, err := c.kvClient(token)
	if err != nil {
		return BulkResult{}, err
	}
	defer client.SetToken("")
	root, err := resolveBulkRoot(ctx, client, destination, opts.KVOptions)
	if err != nil {
		return BulkResult{}, err
	}
	if root.mount.Version == 1 && !opts.Force {
		return BulkResult{}, ErrUnsupportedOperation
	}
	plans := make([]bulkPlanItem, 0, len(archive.Entries))
	outputBytes := 0
	for _, entry := range archive.Entries {
		selected, err := resolveKVTarget(ctx, client, root.logical+"/"+entry.Path, opts.KVOptions)
		if err != nil {
			return BulkResult{}, err
		}
		if !sameBulkMount(root, selected) {
			return BulkResult{}, ErrInvalidPath
		}
		data, err := prepareBulkWrite(selected, entry.Data, opts.Force)
		if err != nil {
			return BulkResult{}, err
		}
		if err := addBulkDataBytes(&outputBytes, data); err != nil {
			return BulkResult{}, err
		}
		plans = append(plans, bulkPlanItem{
			item:   BulkItem{Path: selected.logical, KVVersion: selected.mount.Version},
			target: selected, data: data,
		})
	}
	return executeBulk(ctx, client, "restore", root.logical, "", plans, opts)
}

func bulkRootPath(target string, opts KVOptions) (string, error) {
	logical, _, err := prepareKVPath(target, opts)
	if err != nil {
		return "", err
	}
	if logical == "/" {
		return "", ErrInvalidPath
	}
	return logical, nil
}

func resolveBulkRoot(ctx context.Context, client *api.Client, target string, opts KVOptions) (kvTarget, error) {
	logical, explicit, err := prepareKVPath(target, opts)
	if err != nil {
		return kvTarget{}, err
	}
	if logical == "/" {
		return kvTarget{}, ErrInvalidPath
	}
	mount, err := selectMount(ctx, client, logical, explicit)
	if err != nil {
		return kvTarget{}, err
	}
	key := strings.TrimPrefix(strings.TrimPrefix(logical, "/"+strings.TrimSuffix(mount.Path, "/")), "/")
	return kvTarget{logical: logical, mount: mount, key: key}, nil
}

func sameBulkMount(root, selected kvTarget) bool {
	return root.mount.Path == selected.mount.Path && root.mount.Version == selected.mount.Version
}

func overlappingBulkRoots(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func prepareBulkWrite(target kvTarget, data map[string]any, force bool) (map[string]any, error) {
	normalized, err := normalizeJSONObject(data)
	if err != nil {
		return nil, err
	}
	if target.mount.Version == 1 {
		if !force {
			return nil, ErrUnsupportedOperation
		}
		return normalized, nil
	}
	return validateKV2Numbers(normalized)
}

func addBulkDataBytes(total *int, data map[string]any) error {
	encoded, err := json.Marshal(data)
	if err != nil {
		return ErrInvalidData
	}
	if len(encoded) > MaxTreeDataBytes-*total {
		return ErrTraversalLimit
	}
	*total += len(encoded)
	return nil
}

// executeBulk owns the only mutation stage. Plans and the SDK client's token
// stay immutable until every worker has finished, including in-flight failures.
func executeBulk(ctx context.Context, client *api.Client, operation, root, destination string, plans []bulkPlanItem, opts BulkOptions) (BulkResult, error) {
	result := BulkResult{
		Operation: operation, Root: root, Destination: destination, DryRun: opts.DryRun,
		Items: make([]BulkItem, len(plans)),
	}
	for i, plan := range plans {
		result.Items[i] = plan.item
		result.Items[i].Status = "not_started"
		if plan.unchanged {
			result.Items[i].Status = "unchanged"
			result.Items[i].Version = plan.revision
		} else if opts.DryRun {
			result.Items[i].Status = "planned"
		}
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if opts.DryRun || len(plans) == 0 {
		return result, nil
	}
	var mu sync.Mutex
	var workers sync.WaitGroup
	next, stopped := 0, false
	changed, uncertain := false, false
	var firstErr error
	count := opts.Concurrency
	if count > len(plans) {
		count = len(plans)
	}
	for worker := 0; worker < count; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				mu.Lock()
				if stopped || next == len(plans) {
					mu.Unlock()
					return
				}
				if err := ctx.Err(); err != nil {
					firstErr, stopped = err, true
					mu.Unlock()
					return
				}
				index := next
				next++
				plan := plans[index]
				mu.Unlock()
				if plan.unchanged {
					continue
				}
				version, err := applyBulkPlan(ctx, client, plan)
				mu.Lock()
				if err != nil {
					item := &result.Items[index]
					item.Status, item.Error = "failed", bulkErrorCategory(err)
					if errors.Is(err, errMutationUnconfirmed) {
						item.Status, uncertain = "unconfirmed", true
					}
					if firstErr == nil {
						firstErr = err
					}
					stopped = true
				} else {
					item := &result.Items[index]
					item.Status, item.Version = "written", version
					if plan.deletion {
						item.Status = "deleted"
					}
					changed = true
				}
				mu.Unlock()
			}
		}()
	}
	workers.Wait()
	if firstErr != nil && (changed || uncertain) {
		return result, fmt.Errorf("%w: %w", ErrBulkPartial, firstErr)
	}
	return result, firstErr
}

func applyBulkPlan(ctx context.Context, client *api.Client, plan bulkPlanItem) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if plan.deletion {
		method, physical := http.MethodDelete, plan.target.mount.Path+plan.target.key
		var body map[string]any
		if plan.target.mount.Version == 2 {
			method, physical = http.MethodPost, plan.target.mount.Path+"delete/"+plan.target.key
			body = map[string]any{"versions": []int{plan.revision}}
		}
		_, err := performMutation(ctx, client, method, physical, body)
		return plan.revision, err
	}
	var cas *int
	if plan.target.mount.Version == 2 {
		cas = &plan.revision
	}
	written, err := writeSnapshot(ctx, client, plan.target, plan.data, cas)
	return written.Version, err
}

func bulkErrorCategory(err error) string {
	switch {
	case errors.Is(err, errMutationUnconfirmed):
		return "unconfirmed"
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, ErrUnauthenticated):
		return "permission_denied"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, ErrInvalidData):
		return "invalid_data"
	default:
		return "error"
	}
}
