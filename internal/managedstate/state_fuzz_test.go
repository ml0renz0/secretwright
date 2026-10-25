package managedstate_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ml0renz0/secretwright/internal/managedstate"
)

func FuzzDecode(f *testing.F) {
	valid, err := json.Marshal(testState())
	if err != nil {
		f.Fatal("could not encode inventory fuzz seed")
	}
	empty := testState()
	empty.Resources = []managedstate.Record{}
	blank, err := json.Marshal(empty)
	if err != nil {
		f.Fatal("could not encode empty inventory fuzz seed")
	}
	for _, seed := range [][]byte{valid, blank, []byte(`{"revision":1,"revision":2}`), []byte(`{"token":"private-fuzz-marker"}`), []byte("null"), {0xff, 0x00}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		first, firstErr := managedstate.Decode(bytes.NewReader(input))
		second, secondErr := managedstate.Decode(bytes.NewReader(input))
		if (firstErr == nil) != (secondErr == nil) || !reflect.DeepEqual(first, second) {
			t.Fatal("same inventory bytes decoded nondeterministically")
		}
		if firstErr != nil {
			if firstErr != managedstate.ErrInvalidState || secondErr != managedstate.ErrInvalidState || !reflect.DeepEqual(first, managedstate.State{}) {
				t.Fatal("rejected inventory leaked a partial state or non-static diagnostic")
			}
			return
		}
		if managedstate.Validate(first) != nil {
			t.Fatal("decoded inventory bypassed ownership validation")
		}
		encoded, err := json.Marshal(first)
		if err != nil {
			t.Fatal("accepted ownership metadata could not be encoded")
		}
		again, err := managedstate.Decode(bytes.NewReader(encoded))
		if err != nil || !reflect.DeepEqual(first, again) {
			t.Fatal("accepted inventory changed meaning after a metadata-only round trip")
		}
	})
}
