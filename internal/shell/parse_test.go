package shell_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ml0renz0/secretwright/internal/shell"
)

func TestParsePreservesArgumentsWithoutShellExpansion(t *testing.T) {
	for _, test := range []struct {
		name string
		line string
		want []string
	}{
		{name: "plain", line: "  ls\t/secret/app  ", want: []string{"ls", "/secret/app"}},
		{name: "quoted file", line: `put --file '/tmp/input data.json' /secret/app`, want: []string{"put", "--file", "/tmp/input data.json", "/secret/app"}},
		{name: "escaped whitespace", line: `put --file /tmp/input\ data.json /secret/app`, want: []string{"put", "--file", "/tmp/input data.json", "/secret/app"}},
		{name: "empty quoted argument", line: `cat ""`, want: []string{"cat", ""}},
		{name: "adjacent quote fragments", line: `ls '/secret/'"app"`, want: []string{"ls", "/secret/app"}},
		{name: "literal variable", line: `ls '$VAULT_TOKEN'`, want: []string{"ls", "$VAULT_TOKEN"}},
		{name: "literal backticks", line: "ls '`private-command`'", want: []string{"ls", "`private-command`"}},
		{name: "quoted operator", line: `put --file 'literal|filename' /secret/app`, want: []string{"put", "--file", "literal|filename", "/secret/app"}},
		{name: "inline hash is an argument", line: "ls #literal", want: []string{"ls", "#literal"}},
		{name: "unicode", line: "ls /secret/área/東京", want: []string{"ls", "/secret/área/東京"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := shell.Parse(test.line)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Errorf("argument parsing changed literal input: got %q, error %v", got, err)
			}
		})
	}
	for _, line := range []string{"", " \t ", "# a comment", " \t# another comment"} {
		args, err := shell.Parse(line)
		if err != nil || len(args) != 0 {
			t.Error("blank or whole-line comment was treated as a command")
		}
	}
}

func TestParseRejectsUnsafeOrIncompleteInputWithoutEchoingIt(t *testing.T) {
	for _, line := range []string{
		`cat 'private-input-marker`, `cat "private-input-marker`, "cat private-input-marker\\",
		"ls /secret | private-input-marker", "ls;private-input-marker", "ls & private-input-marker",
		"cat < private-input-marker", "cat > private-input-marker", "ls\x00private-input-marker",
		"ls\x1bprivate-input-marker", "ls\x7fprivate-input-marker", "ls\nprivate-input-marker",
		"ls\rprivate-input-marker", string([]byte{'l', 's', ' ', 0xff}),
	} {
		_, err := shell.Parse(line)
		if !errors.Is(err, shell.ErrInvalidLine) {
			t.Errorf("invalid shell syntax classification = %v", err)
		}
		if err != nil && strings.Contains(err.Error(), "private-input-marker") {
			t.Error("parser error reproduced rejected input")
		}
	}
}

func TestParseBoundsWholeLineWithoutExecutingATruncatedPrefix(t *testing.T) {
	line := "ls " + strings.Repeat("a", shell.MaxLineBytes-3)
	args, err := shell.Parse(line)
	if err != nil || len(args) != 2 || len(args[1]) != shell.MaxLineBytes-3 {
		t.Fatal("a complete line at the byte limit was not preserved")
	}
	if _, err := shell.Parse(line + "private-input-marker"); !errors.Is(err, shell.ErrLineTooLong) {
		t.Errorf("oversized shell input classification = %v", err)
	}
}

func TestSafeHistoryUsesAnExplicitMetadataOnlyAllowlist(t *testing.T) {
	for _, args := range [][]string{
		{"help"}, {"version"}, {"pwd"}, {"status"}, {"mounts"}, {"ls"}, {"ls", "/secret/app"},
		{"cd", "../app"}, {"versions", "/secret/app"},
	} {
		line, ok := shell.SafeHistory(args)
		if !ok || line != strings.Join(args, " ") {
			t.Errorf("safe command was not recorded in normalized form: %q", args)
		}
	}
	for _, args := range [][]string{
		nil, {"cat", "/secret/private"}, {"auth", "check"}, {"put", "--file", "private-input-marker", "/secret/app"},
		{"rm", "/secret/app"}, {"cp", "/secret/a", "/secret/b"}, {"mv", "/secret/a", "/secret/b"},
		{"undelete", "--versions", "1", "/secret/app"}, {"destroy", "/secret/app"}, {"rollback", "/secret/app", "1"},
		{"history"}, {"exit"}, {"unknown", "private-input-marker"}, {"status", "--token-file", "private-input-marker"},
		{"ls", "--mount", "secret", "/secret/app"}, {"ls", "--address=private-input-marker"},
		{"ls", "one", "two"}, {"ls", "private input marker"}, {"cd", "private\ninput"},
	} {
		if line, ok := shell.SafeHistory(args); ok || line != "" {
			t.Error("history accepted a command outside its explicit safe allowlist")
		}
	}
}
