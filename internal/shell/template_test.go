package shell_test

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/ml0renz0/secretwright/internal/shell"
)

func TestTemplateCompletionOnlyOffersTheRootCommandAndNeverListsFiles(t *testing.T) {
	var calls atomic.Int32
	list := func(context.Context, string, string) ([]string, error) {
		calls.Add(1)
		return nil, errors.New("must not consult Vault")
	}
	line := []rune("tem")
	got, length := shell.Complete(context.Background(), line, len(line), "/secret", list)
	if !reflect.DeepEqual(completionStrings(got), []string{"plate "}) || length != 3 {
		t.Error("template was missing from command-name completion")
	}
	for _, text := range []string{"template ", "template show ", "template render ", "template render --file /tmp/", "template schema "} {
		line := []rune(text)
		if got, _ := shell.Complete(context.Background(), line, len(line), "/secret", list); len(got) != 0 {
			t.Error("template completion exposed local paths, values or remote names")
		}
	}
	if calls.Load() != 0 {
		t.Error("offline template completion contacted Vault")
	}
	for _, args := range [][]string{{"template", "list"}, {"template", "show", "single-app"}, {"template", "render", "--file", "architecture.yaml"}, {"template", "schema"}} {
		if line, ok := shell.SafeHistory(args); ok || line != "" {
			t.Error("template configuration entered shell history")
		}
	}
}
