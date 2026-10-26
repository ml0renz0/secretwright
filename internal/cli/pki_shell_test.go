package cli

import (
	"reflect"
	"testing"
)

func TestPKISessionConnectionFollowsOnlyOnlinePrefixes(t *testing.T) {
	options, _, err := parseShellOptions([]string{"--address", "https://vault.example", "--namespace", "team", "--timeout", "7s", "--token-file", "operator-token"})
	if err != nil {
		t.Fatal("could not prepare PKI session options")
	}
	connection := []string{"--address", "https://vault.example", "--namespace", "team", "--timeout", "7s", "--token-file", "operator-token"}
	for _, action := range []string{"ca", "read", "issue", "sign", "revoke"} {
		prefix := []string{"pki", action}
		words := append(append([]string{}, prefix...), "--mount", "pki")
		want := append(append(append([]string{}, prefix...), connection...), "--mount", "pki")
		if got := options.commandArgs(words, "/unused-kv-cwd"); !reflect.DeepEqual(got, want) {
			t.Error("PKI connection was injected outside its action prefix or inherited KV cwd")
		}
	}
	for _, words := range [][]string{
		{"pki", "schema"}, {"pki", "example", "--format", "json"}, {"pki", "validate", "--file", "request.yaml"},
		{"pki", "cert", "inspect", "--file", "cert.pem"}, {"pki", "cert", "verify", "--file", "cert.pem", "--ca-file", "roots.pem"},
		{"pki", "cert", "match", "--file", "cert.pem", "--key", "key.pem"}, {"pki", "key", "inspect", "--file", "key.pem"},
		{"pki", "csr", "inspect", "--file", "csr.pem"}, {"pki", "csr", "create", "--file", "request.yaml", "--key-out", "key.pem", "--out", "csr.pem"},
	} {
		if got := options.commandArgs(words, "/unused-kv-cwd"); !reflect.DeepEqual(got, words) {
			t.Error("offline PKI command inherited the session connection")
		}
	}
	for _, words := range [][]string{
		{"pki", "revoke", "--force", "--address", "https://foreign.example"},
		{"pki", "revoke", "--force=true", "--namespace", "foreign"},
		{"pki", "cert", "verify", "--hostname", "api.example.test", "--token-file", "foreign-token"},
		{"pki", "issue", "--mount=pki", "--file", "request.yaml", "--cwd", "/foreign"},
	} {
		if !shellOverrides(words) {
			t.Error("PKI shell override guard skipped a connection option after its nested or boolean flags")
		}
	}
}
