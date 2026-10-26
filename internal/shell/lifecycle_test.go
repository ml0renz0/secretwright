package shell_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/ml0renz0/secretwright/internal/shell"
)

func TestLifecycleCompletionIsRootOnlyAndNeverEnumeratesSecrets(t *testing.T) {
	calls := 0
	list := func(context.Context, string, string) ([]string, error) {
		calls++
		return []string{"private-secret-name"}, nil
	}
	line := []rune("life")
	values, length := shell.Complete(context.Background(), line, len(line), "/", list)
	if !reflect.DeepEqual(completionStrings(values), []string{"cycle "}) || length != 4 {
		t.Error("lifecycle was not offered as a root command")
	}
	for _, text := range []string{"lifecycle ", "lifecycle token ", "lifecycle token inspect ", "lifecycle lease revoke private", "lifecycle rotate private"} {
		line = []rune(text)
		values, _ = shell.Complete(context.Background(), line, len(line), "/secret", list)
		if len(values) != 0 {
			t.Error("lifecycle completion offered a private file or logical secret path")
		}
	}
	if calls != 0 {
		t.Error("lifecycle completion contacted Vault")
	}
}
