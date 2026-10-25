package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/managedstate"
	"github.com/ml0renz0/secretwright/internal/vault"
)

func blueprintOnline(action string) bool {
	return action == "plan" || action == "apply" || action == "adopt" || action == "recover"
}

// Load local evidence before selecting a credential or inspecting network
// settings. Apply and recovery hold the cooperative lock through all checkpoints.
func managedBlueprintCommand(ctx context.Context, options blueprintCommandOptions, document blueprint.Document, stdout, stderr io.Writer) (code int) {
	var state managedstate.State
	var store *managedstate.Store
	var err error
	switch options.action {
	case "adopt":
		if _, pathErr := os.Lstat(options.state); pathErr == nil {
			return blueprintError(stderr, managedstate.ErrStateChanged)
		} else if !errors.Is(pathErr, os.ErrNotExist) {
			return blueprintError(stderr, managedstate.ErrStateIO)
		}
	case "plan":
		state, err = managedstate.Read(options.state)
	default:
		store, err = managedstate.Lock(options.state)
		if err == nil {
			state = store.Snapshot()
			defer func() {
				changed := store.Snapshot().Revision != state.Revision
				if closeErr := store.Close(); closeErr != nil && code == 0 {
					if changed {
						closeErr = errors.Join(blueprint.ErrPartial, closeErr)
					}
					code = blueprintError(stderr, closeErr)
				}
			}()
		}
	}
	if err != nil {
		return blueprintError(stderr, err)
	}
	token, err := vault.LoadToken(options.network.tokenFile)
	if err != nil {
		return blueprintError(stderr, err)
	}
	client, err := vault.New(options.network.vault)
	if err != nil {
		return blueprintError(stderr, err)
	}
	ctx, cancel := context.WithTimeout(ctx, client.OperationTimeout())
	defer cancel()
	binding, err := client.ReconciliationTarget(ctx)
	if err != nil {
		return blueprintError(stderr, err)
	}
	target := managedstate.Target{AddressSHA256: binding.AddressSHA256, ClusterID: binding.ClusterID, Namespace: binding.Namespace}
	backend := blueprint.NewManagedVaultBackend(client, token)
	if options.action == "plan" {
		plan, planErr := blueprint.BuildManagedPlan(ctx, document, backend, state, target, options.repair)
		if planErr == nil || errors.Is(planErr, blueprint.ErrConflict) && len(plan.Resources) != 0 {
			if code := writeManagedJSON(stdout, stderr, plan); code != 0 {
				return code
			}
		}
		if planErr != nil {
			return blueprintError(stderr, planErr)
		}
		return 0
	}
	var report blueprint.ManagedReport
	switch options.action {
	case "adopt":
		var adopted managedstate.State
		adopted, report, err = blueprint.Adopt(ctx, document, backend, target)
		if err == nil {
			err = managedstate.Create(options.state, adopted)
		}
		if err != nil {
			return blueprintError(stderr, err)
		}
	case "apply":
		report, err = blueprint.ApplyManaged(ctx, document, backend, store, target, options.repair)
	case "recover":
		report, err = blueprint.RecoverManaged(ctx, document, backend, store, target, options.adoptPending)
	}
	if len(report.Items) != 0 || err == nil {
		if code := writeManagedJSON(stdout, stderr, report); code != 0 {
			return code
		}
	}
	if err != nil {
		return blueprintError(stderr, err)
	}
	return 0
}

func writeManagedJSON(stdout, stderr io.Writer, value any) int {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return commandError(stderr, errors.New("could not encode managed blueprint output"))
	}
	body = append(body, '\n')
	written, err := stdout.Write(body)
	if err != nil || written != len(body) {
		return commandError(stderr, errors.New("could not write managed blueprint output"))
	}
	return 0
}
