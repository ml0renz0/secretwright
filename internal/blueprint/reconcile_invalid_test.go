package blueprint_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ml0renz0/secretwright/internal/blueprint"
	"github.com/ml0renz0/secretwright/internal/managedstate"
)

type f09InvalidSink struct {
	state managedstate.State
	saves int
}

func (sink *f09InvalidSink) Snapshot() managedstate.State { return sink.state }
func (sink *f09InvalidSink) Save(managedstate.State) error {
	sink.saves++
	return managedstate.ErrStateIO
}

func TestManagedEntryPointsNeverRepairAnInvalidNilInventory(t *testing.T) {
	document := f07LoadDocument(t, f07PolicyResource("a"))
	state := managedstate.State{APIVersion: managedstate.APIVersion, Blueprint: document.Name, Target: f09Target(), Revision: 1}
	if managedstate.Validate(state) == nil {
		t.Fatal("nil inventory fixture was unexpectedly valid")
	}
	backend := f09NewBackend()
	ctx := context.Background()
	if _, err := blueprint.BuildManagedPlan(ctx, document, backend, state, f09Target(), false); !errors.Is(err, managedstate.ErrInvalidState) {
		t.Error("planning silently repaired an invalid inventory")
	}
	sink := &f09InvalidSink{state: state}
	if _, err := blueprint.ApplyManaged(ctx, document, backend, sink, f09Target(), false); !errors.Is(err, managedstate.ErrInvalidState) {
		t.Error("application silently repaired an invalid inventory")
	}
	if _, err := blueprint.RecoverManaged(ctx, document, backend, sink, f09Target(), false); !errors.Is(err, managedstate.ErrInvalidState) {
		t.Error("recovery silently repaired an invalid inventory")
	}
	if len(backend.events) != 0 || backend.writes != 0 || sink.saves != 0 {
		t.Error("invalid local evidence caused backend calls or state checkpoints")
	}
}
