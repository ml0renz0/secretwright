package shell

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ml0renz0/secretwright/internal/vault"
)

// Lister returns immediate child names using the session's connection and token.
// Complete supplies an absolute canonical parent and the current session cwd.
type Lister func(context.Context, string, string) ([]string, error)

var completionCommands = []string{
	"approle", "auth", "backup", "blueprint", "cat", "cd", "cp", "cptree", "destroy", "exit", "find",
	"help", "history", "identity", "keytab", "lifecycle", "ls", "mounts", "mv", "pki", "policy", "put", "pwd", "quit", "replace",
	"restore", "rm", "rmtree", "rollback", "status", "template", "token", "tree", "undelete", "version", "versions",
}

// Complete returns suffixes for readline's API. Completion never reads secret
// values or local files, and any failure is deliberately silent.
func Complete(ctx context.Context, line []rune, pos int, cwd string, list Lister) ([][]rune, int) {
	if pos != len(line) || pos < 0 || ctx.Err() != nil {
		return nil, 0
	}
	for _, character := range line {
		if !utf8.ValidRune(character) || (unicode.IsControl(character) && character != '\t') {
			return nil, 0
		}
	}
	text := string(line)
	if len(text) > MaxLineBytes || strings.ContainsAny(text, "'\"\\|&;<>") {
		return nil, 0
	}
	arguments, err := Parse(text)
	if err != nil || strings.HasPrefix(strings.TrimLeft(text, " \t"), "#") {
		return nil, 0
	}
	for _, argument := range arguments {
		if strings.HasPrefix(argument, "-") {
			return nil, 0
		}
	}
	if len(arguments) == 0 || strings.HasSuffix(text, " ") || strings.HasSuffix(text, "\t") {
		arguments = append(arguments, "")
	}
	current := arguments[len(arguments)-1]
	length := utf8.RuneCountInString(current)
	if len(arguments) == 1 {
		suffixes := commandSuffixes(current)
		if len(suffixes) == 0 {
			return nil, 0
		}
		return suffixes, length
	}
	if list == nil || !pathPosition(arguments[0], len(arguments)-1) {
		return nil, 0
	}
	parent, base := ".", current
	pathPrefix := ""
	if slash := strings.LastIndex(current, "/"); slash >= 0 {
		parent, base = current[:slash], current[slash+1:]
		pathPrefix = current[:slash+1]
		if parent == "" {
			parent = "/"
		}
	}
	canonical, err := vault.ResolvePath(cwd, parent)
	if err != nil {
		return nil, 0
	}
	if _, err := vault.ResolvePath(cwd, current); err != nil {
		return nil, 0
	}
	ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	type response struct {
		names []string
		err   error
	}
	completed := make(chan response, 1)
	go func() {
		names, err := list(ctx, canonical, cwd)
		completed <- response{names: names, err: err}
	}()
	var names []string
	select {
	case <-ctx.Done():
		return nil, 0
	case result := <-completed:
		if result.err != nil || ctx.Err() != nil {
			return nil, 0
		}
		names = result.names
	}
	unique := make(map[string]struct{}, len(names))
	for _, name := range names {
		segment := strings.TrimSuffix(name, "/")
		if segment == "" || segment == "." || segment == ".." || strings.Contains(segment, "/") || strings.ContainsAny(name, "'\"\\|&;<>") {
			continue
		}
		if _, err := vault.ResolvePath("/", name); err != nil {
			continue
		}
		if pathPrefix == "" && strings.HasPrefix(name, "-") {
			continue
		}
		if strings.HasPrefix(name, base) {
			unique[name] = struct{}{}
		}
	}
	ordered := make([]string, 0, len(unique))
	for name := range unique {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	if len(ordered) > 100 {
		ordered = ordered[:100]
	}
	var suffixes [][]rune
	for _, name := range ordered {
		suffix := strings.TrimPrefix(name, base)
		if !strings.HasSuffix(name, "/") {
			suffix += " "
		}
		suffixes = append(suffixes, []rune(suffix))
	}
	if len(suffixes) == 0 {
		return nil, 0
	}
	return suffixes, length
}

func commandSuffixes(prefix string) [][]rune {
	var suffixes [][]rune
	for _, command := range completionCommands {
		if strings.HasPrefix(command, prefix) {
			suffixes = append(suffixes, []rune(strings.TrimPrefix(command, prefix)+" "))
		}
	}
	return suffixes
}

func pathPosition(command string, position int) bool {
	switch command {
	case "ls", "cd", "cat", "put", "rm", "versions", "undelete", "destroy", "rollback",
		"tree", "find", "replace", "rmtree", "backup", "restore":
		return position == 1
	case "cp", "mv", "cptree":
		return position == 1 || position == 2
	}
	return false
}
