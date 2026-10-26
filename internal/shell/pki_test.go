package shell_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/ml0renz0/secretwright/internal/shell"
)

func TestPKICompletionIsRootOnlyAndHistoryExcludesPrivateOperations(t *testing.T) {
	calls := 0
	list := func(context.Context, string, string) ([]string, error) {
		calls++
		return []string{"private-pki-name"}, nil
	}
	line := []rune("pk")
	values, length := shell.Complete(context.Background(), line, len(line), "/", list)
	if !reflect.DeepEqual(completionStrings(values), []string{"i "}) || length != 2 {
		t.Error("PKI was not offered as a root command")
	}
	for _, text := range []string{"pki ", "pki cert ", "pki cert inspect ", "pki issue private", "pki read private"} {
		line = []rune(text)
		values, _ := shell.Complete(context.Background(), line, len(line), "/secret", list)
		if len(values) != 0 {
			t.Error("PKI completion enumerated private paths or values")
		}
	}
	for _, args := range [][]string{
		{"pki", "schema"}, {"pki", "example"}, {"pki", "cert", "inspect", "--file", "private-cert.pem"},
		{"pki", "key", "inspect", "--file", "private-key.pem"}, {"pki", "csr", "create", "--file", "request.yaml"},
		{"pki", "issue", "--role", "private-role"}, {"pki", "revoke", "--force", "--file", "cert.pem"},
	} {
		if line, accepted := shell.SafeHistory(args); accepted || line != "" {
			t.Error("PKI input entered searchable shell history")
		}
	}
	if calls != 0 {
		t.Error("PKI completion contacted Vault")
	}
}
