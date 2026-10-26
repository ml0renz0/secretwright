package shell_test

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ml0renz0/secretwright/internal/shell"
	"github.com/ml0renz0/secretwright/internal/vault"
)

func completionStrings(values [][]rune) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = string(value)
	}
	return result
}

func TestCompletionUsesCommandNamesWithoutConsultingVault(t *testing.T) {
	var calls atomic.Int32
	list := func(context.Context, string, string) ([]string, error) {
		calls.Add(1)
		return nil, errors.New("must not be consulted")
	}
	for _, test := range []struct {
		line string
		want []string
	}{
		{line: "p", want: []string{"ki ", "olicy ", "ut ", "wd "}},
		{line: "ap", want: []string{"prole "}},
		{line: "blu", want: []string{"eprint "}},
		{line: "ident", want: []string{"ity "}},
		{line: "tok", want: []string{"en "}},
		{line: "q", want: []string{"uit "}},
		{line: "hist", want: []string{"ory "}},
	} {
		line := []rune(test.line)
		got, length := shell.Complete(context.Background(), line, len(line), "/", list)
		if !reflect.DeepEqual(completionStrings(got), test.want) || length != len(line) {
			t.Errorf("command completion = %q, prefix length %d", completionStrings(got), length)
		}
	}
	if calls.Load() != 0 {
		t.Error("command-name completion consulted Vault")
	}
}

func TestPathCompletionListsOnlyTheCurrentParentAndReturnsNames(t *testing.T) {
	for _, test := range []struct {
		line   string
		cwd    string
		parent string
		want   []string
	}{
		{line: "ls /secret/ap", cwd: "/", parent: "/secret", want: []string{"p/", "ple "}},
		{line: "cat ap", cwd: "/secret", parent: "/secret", want: []string{"p/", "ple "}},
		{line: "cd ../ap", cwd: "/secret/nested", parent: "/secret", want: []string{"p/", "ple "}},
		{line: "cp source /secret/ap", cwd: "/", parent: "/secret", want: []string{"p/", "ple "}},
		{line: "mv /secret/source ap", cwd: "/secret", parent: "/secret", want: []string{"p/", "ple "}},
		{line: "rollback /secret/ap", cwd: "/", parent: "/secret", want: []string{"p/", "ple "}},
	} {
		t.Run(test.line, func(t *testing.T) {
			var calls atomic.Int32
			list := func(ctx context.Context, parent, cwd string) ([]string, error) {
				calls.Add(1)
				canonical, err := vault.ResolvePath(cwd, parent)
				if err != nil || canonical != test.parent || cwd != test.cwd {
					t.Error("completion enumerated a different logical directory or working directory")
				}
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 600*time.Millisecond {
					t.Error("completion failed to bound the remote lookup")
				}
				return []string{"banana", "apple", "app/", "app/"}, nil
			}
			line := []rune(test.line)
			got, _ := shell.Complete(context.Background(), line, len(line), test.cwd, list)
			if !reflect.DeepEqual(completionStrings(got), test.want) || calls.Load() != 1 {
				t.Errorf("path completion = %q after %d lookups", completionStrings(got), calls.Load())
			}
		})
	}
}

func TestCompletionHandlesUnicodeAndDoesNotCacheRemoteNames(t *testing.T) {
	var calls atomic.Int32
	list := func(context.Context, string, string) ([]string, error) {
		if calls.Add(1) == 1 {
			return []string{"área/"}, nil
		}
		return []string{"árbol"}, nil
	}
	line := []rune("ls /secret/á")
	first, firstLength := shell.Complete(context.Background(), line, len(line), "/", list)
	second, secondLength := shell.Complete(context.Background(), line, len(line), "/", list)
	if !reflect.DeepEqual(completionStrings(first), []string{"rea/"}) || !reflect.DeepEqual(completionStrings(second), []string{"rbol "}) || calls.Load() != 2 || firstLength != len([]rune("/secret/á")) || secondLength != firstLength {
		t.Error("completion changed Unicode prefixes or reused stale remote names")
	}
}

func TestCompletionSkipsOptionValuesQuotedInputAndNonPathArguments(t *testing.T) {
	var calls atomic.Int32
	list := func(context.Context, string, string) ([]string, error) {
		calls.Add(1)
		return []string{"private-remote-name"}, nil
	}
	for _, text := range []string{
		"put --file /tmp/", "cat --token-file /tmp/", "ls --mount secret /secret/ap",
		"ls --namespace team /secret/ap", `ls "/secret/ap`, `ls /secret/a\p`,
		"ls /secret | cat", "rollback /secret/app 2", "auth check ", "status ", "history ",
		"shell ", "cp /secret/a /secret/b extra", "unknown /secret/",
		"blueprint plan ", "blueprint validate --file /tmp/",
	} {
		line := []rune(text)
		got, _ := shell.Complete(context.Background(), line, len(line), "/", list)
		if len(got) != 0 {
			t.Error("completion offered names for an option, unsupported syntax, or non-path argument")
		}
	}
	line := []rune("ls /secret/app")
	if got, _ := shell.Complete(context.Background(), line, len(line)-1, "/", list); len(got) != 0 {
		t.Error("completion altered a line with the cursor before its end")
	}
	if calls.Load() != 0 {
		t.Error("completion queried Vault for an option or unsupported argument")
	}
}

func TestCompletionReturnsNoNamesForDenialCancellationOrTimeout(t *testing.T) {
	line := []rune("cat /secret/app")
	for _, denied := range []error{vault.ErrPermissionDenied, vault.ErrUnauthenticated, vault.ErrNotFound} {
		got, _ := shell.Complete(context.Background(), line, len(line), "/", func(context.Context, string, string) ([]string, error) {
			return []string{"private-name-must-not-leak"}, denied
		})
		if len(got) != 0 {
			t.Error("completion exposed partial names after a failed lookup")
		}
	}
	started := time.Now()
	got, _ := shell.Complete(context.Background(), line, len(line), "/", func(ctx context.Context, _, _ string) ([]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if len(got) != 0 || time.Since(started) > 2*time.Second {
		t.Error("remote completion exceeded its bounded lookup or returned names after timeout")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, _ = shell.Complete(ctx, line, len(line), "/", func(ctx context.Context, _, _ string) ([]string, error) {
		return nil, ctx.Err()
	})
	if len(got) != 0 {
		t.Error("canceled completion returned names")
	}
}

func TestCompletionBoundsAndSortsSuggestions(t *testing.T) {
	line := []rune("ls /secret/")
	got, _ := shell.Complete(context.Background(), line, len(line), "/", func(context.Context, string, string) ([]string, error) {
		names := make([]string, 0, 150)
		for i := 149; i >= 0; i-- {
			names = append(names, "item-"+strconv.Itoa(i))
		}
		return names, nil
	})
	values := completionStrings(got)
	if len(values) != 100 || !sort.StringsAreSorted(values) {
		t.Error("completion did not bound and sort its candidate set")
	}
	for _, value := range values {
		if !strings.HasSuffix(value, " ") {
			t.Error("file candidate did not separate the following argument")
		}
	}
}
