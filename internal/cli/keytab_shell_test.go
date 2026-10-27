package cli

import (
	"reflect"
	"testing"
)

func TestKeytabSessionInjectsOnlyTheOnlineActionConnection(t *testing.T) {
	options, _, err := parseShellOptions([]string{"--address", "https://vault.example", "--namespace", "team", "--timeout", "7s", "--token-file", "operator-token"})
	if err != nil {
		t.Fatal("could not prepare keytab session options")
	}
	connection := []string{"--address", "https://vault.example", "--namespace", "team", "--timeout", "7s", "--token-file", "operator-token"}
	for _, action := range []string{"import", "export"} {
		words := []string{"keytab", action, "--mount", "secret", "--path", "/secret/keytabs/app"}
		want := append(append([]string{"keytab", action}, connection...), words[2:]...)
		if got := options.commandArgs(words, "/unrelated-cwd"); !reflect.DeepEqual(got, want) {
			t.Error("keytab transfer lost the fixed connection or inherited KV cwd")
		}
	}
	for _, words := range [][]string{
		{"keytab", "schema"}, {"keytab", "example", "--format", "json"},
		{"keytab", "inspect", "--file", "service.keytab"}, {"keytab", "validate", "--file", "service.keytab", "--policy", "policy.yaml"},
	} {
		if got := options.commandArgs(words, "/unrelated-cwd"); !reflect.DeepEqual(got, words) {
			t.Error("offline keytab command inherited operator connection or credentials")
		}
	}
	for _, words := range [][]string{
		{"keytab", "import", "--cas", "3", "--address", "https://foreign.example"},
		{"keytab", "export", "--version=3", "--namespace", "foreign"},
		{"keytab", "export", "--help", "--token-file", "foreign-token"},
		{"keytab", "validate", "--policy", "policy.yaml", "--cwd", "/foreign"},
	} {
		if !shellOverrides(words) {
			t.Error("keytab shell override scan skipped a fixed connection option")
		}
	}
}
