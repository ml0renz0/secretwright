package shell_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/ml0renz0/secretwright/internal/shell"
)

func TestKeytabCompletionAndHistoryNeverExposePrivateInputs(t *testing.T) {
	calls := 0
	list := func(context.Context, string, string) ([]string, error) {
		calls++
		return []string{"private-keytab-name"}, nil
	}
	line := []rune("key")
	got, length := shell.Complete(context.Background(), line, len(line), "/", list)
	if !reflect.DeepEqual(completionStrings(got), []string{"tab "}) || length != 3 {
		t.Error("keytab was not offered as a root command")
	}
	for _, text := range []string{"keytab ", "keytab inspect ", "keytab import private", "keytab export --out private"} {
		line = []rune(text)
		got, _ := shell.Complete(context.Background(), line, len(line), "/secret", list)
		if len(got) != 0 {
			t.Error("keytab completion enumerated private files, principals or Vault values")
		}
	}
	for _, args := range [][]string{
		{"keytab", "schema"}, {"keytab", "example"}, {"keytab", "inspect", "--file", "private.keytab"},
		{"keytab", "validate", "--file", "private.keytab", "--policy", "policy.yaml"},
		{"keytab", "import", "--file", "private.keytab"}, {"keytab", "export", "--out", "private.keytab"},
	} {
		if line, accepted := shell.SafeHistory(args); accepted || line != "" {
			t.Error("keytab input entered searchable shell history")
		}
	}
	if calls != 0 {
		t.Error("keytab completion contacted Vault")
	}
}
