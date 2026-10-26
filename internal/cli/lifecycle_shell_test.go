package cli

import (
	"reflect"
	"testing"
)

func TestLifecycleSessionConnectionOptionsFollowEveryOnlinePrefix(t *testing.T) {
	options, _, err := parseShellOptions([]string{"--address", "https://vault.example", "--namespace", "team", "--timeout", "7s", "--token-file", "operator-token"})
	if err != nil {
		t.Fatal("could not prepare session options")
	}
	connection := []string{"--address", "https://vault.example", "--namespace", "team", "--timeout", "7s", "--token-file", "operator-token"}
	for _, prefix := range [][]string{
		{"lifecycle", "inspect"}, {"lifecycle", "rotate"},
		{"lifecycle", "retire"}, {"lifecycle", "recover"},
		{"lifecycle", "token", "inspect"}, {"lifecycle", "token", "renew"},
		{"lifecycle", "lease", "inspect"}, {"lifecycle", "lease", "renew"}, {"lifecycle", "lease", "revoke"},
	} {
		words := append(append([]string(nil), prefix...), "--file", "private-input")
		want := append(append(append([]string(nil), prefix...), connection...), "--file", "private-input")
		if got := options.commandArgs(words, "/unused-kv-cwd"); !reflect.DeepEqual(got, want) {
			t.Error("lifecycle session connection was injected outside its action prefix or inherited KV cwd")
		}
	}
	for _, words := range [][]string{
		{"lifecycle", "schema"}, {"lifecycle", "example", "--format", "json"},
		{"lifecycle", "validate", "--file", "private-input"},
	} {
		if got := options.commandArgs(words, "/unused-kv-cwd"); !reflect.DeepEqual(got, words) {
			t.Error("offline lifecycle action inherited the session connection")
		}
	}
}
