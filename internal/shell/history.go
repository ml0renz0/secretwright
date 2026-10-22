package shell

import (
	"strings"

	"github.com/ml0renz0/secretwright/internal/vault"
)

// SafeHistory constructs a fresh, re-executable line from the narrow history
// allowlist. Callers add it only after successful execution, never from raw input.
func SafeHistory(arguments []string) (string, bool) {
	if len(arguments) == 0 {
		return "", false
	}
	switch arguments[0] {
	case "help", "version", "pwd", "status", "mounts":
		if len(arguments) == 1 {
			return arguments[0], true
		}
	case "ls", "cd", "versions":
		if len(arguments) == 1 {
			return arguments[0], true
		}
		if len(arguments) != 2 || arguments[1] == "" || strings.HasPrefix(arguments[1], "-") {
			return "", false
		}
		if _, err := vault.ResolvePath("/", arguments[1]); err != nil {
			return "", false
		}
		line := arguments[0] + " " + historyArgument(arguments[1])
		if len(line) > MaxLineBytes {
			return "", false
		}
		return line, true
	}
	return "", false
}

func historyArgument(argument string) string {
	if !strings.ContainsAny(argument, "'\"\\|&;<>$`") {
		return argument
	}
	// Single-quote literal spans, escaping a quote outside those spans. Parse
	// understands this representation without evaluating any contained text.
	return "'" + strings.ReplaceAll(argument, "'", "'\\''") + "'"
}
