package shell_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/ml0renz0/secretwright/internal/shell"
)

func TestCompletionNeverTurnsRemoteNamesIntoOptionsOrExtraArguments(t *testing.T) {
	names := []string{
		"normal", "normal", "área/", "$literal", "--force",
		".", "..", "../outside", "/outside", "nested/item", "nested//",
		"two arguments", "tab\targument", "line\nargument", "carriage\rreturn",
		"nul\x00name", "escape\x1b[2J", "delete\x7f", string([]byte{0xff}),
		"percent%2fname", "query?name", "fragment#name", `back\slash`,
		`single'quote`, `double"quote`, "pipe|command", "and&command", "semi;command", "input<file", "output>file",
	}
	for _, test := range []struct {
		line string
		want []string
	}{
		{line: "ls ", want: []string{"$literal ", "normal ", "área/"}},
		{line: "ls /secret/", want: []string{"$literal ", "--force ", "normal ", "área/"}},
	} {
		t.Run(test.line, func(t *testing.T) {
			line := []rune(test.line)
			got, _ := shell.Complete(context.Background(), line, len(line), "/secret", func(context.Context, string, string) ([]string, error) {
				return names, nil
			})
			if !reflect.DeepEqual(completionStrings(got), test.want) {
				t.Error("remote completion displayed unsafe names, injected a flag, or lost safe literal names")
			}
			for _, suffix := range got {
				args, err := shell.Parse(test.line + string(suffix))
				if err != nil || len(args) != 2 || args[0] != "ls" {
					t.Error("a completion candidate changed the number or syntax of command arguments")
				}
			}
		})
	}
}
