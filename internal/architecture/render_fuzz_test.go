package architecture_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ml0renz0/secretwright/internal/architecture"
	"github.com/ml0renz0/secretwright/internal/blueprint"
)

func FuzzRender(f *testing.F) {
	for _, kind := range []string{"single-user", "multi-user", "single-app", "multi-app", "multi-env", "saas"} {
		input, err := json.Marshal(map[string]any{"api_version": "secretwright/architecture/v1", "name": "platform", "instances": []map[string]any{f08Instance(kind, "main", "project")}})
		if err != nil {
			f.Fatal("could not encode a fuzz seed")
		}
		f.Add(input)
	}
	f.Add([]byte("api_version: secretwright/architecture/v1\nname: &private-marker platform\ninstances: []\n"))
	f.Add([]byte("\xff\x00"))
	f.Fuzz(func(t *testing.T, input []byte) {
		first, firstErr := architecture.Render(bytes.NewReader(input))
		second, secondErr := architecture.Render(bytes.NewReader(input))
		if (firstErr == nil) != (secondErr == nil) || !bytes.Equal(first, second) {
			t.Fatal("identical architecture input produced different bytes or acceptance")
		}
		if firstErr != nil {
			if firstErr != architecture.ErrInvalidTemplate || secondErr != architecture.ErrInvalidTemplate || len(first) != 0 {
				t.Fatal("failed architecture render leaked input or a partial configuration")
			}
			return
		}
		if len(first) == 0 || len(first) > blueprint.MaxExpandedBytes || first[len(first)-1] != '\n' || !json.Valid(first) {
			t.Fatal("successful render exceeded its bounds or emitted incomplete JSON")
		}
		document, err := blueprint.Load(bytes.NewReader(first), nil)
		if err != nil || len(document.Resources) == 0 || len(document.Resources) > blueprint.MaxResources {
			t.Fatal("successful render produced a configuration the blueprint engine cannot execute")
		}
		again, err := blueprint.ValidateDocument(document)
		if err != nil || !reflect.DeepEqual(document, again) {
			t.Fatal("rendered blueprint changed when validated for execution")
		}
	})
}
