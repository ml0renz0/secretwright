// Package shell provides a bounded command session without an operating-system shell.
package shell

import (
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxLineBytes = 64 * 1024

var (
	ErrInterrupt   = errors.New("shell input interrupted")
	ErrLineTooLong = errors.New("shell input line exceeds 64 KiB")
	ErrInvalidLine = errors.New("invalid shell command syntax")
)

// Parse recognizes arguments, quoting and literal escapes. It never performs
// expansion or interprets a command as an operating-system shell program.
func Parse(line string) ([]string, error) {
	if len(line) > MaxLineBytes {
		return nil, ErrLineTooLong
	}
	if !utf8.ValidString(line) {
		return nil, ErrInvalidLine
	}
	for _, character := range line {
		if unicode.IsControl(character) && character != '\t' {
			return nil, ErrInvalidLine
		}
	}
	if strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
		return nil, nil
	}
	var arguments []string
	var word strings.Builder
	var quote rune
	var escaped, started bool
	flush := func() {
		if started {
			arguments = append(arguments, word.String())
			word.Reset()
			started = false
		}
	}
	for _, character := range line {
		if escaped {
			if unicode.IsControl(character) {
				return nil, ErrInvalidLine
			}
			word.WriteRune(character)
			escaped = false
			started = true
			continue
		}
		if quote != 0 {
			if character == '\t' {
				return nil, ErrInvalidLine
			}
			if character == quote {
				quote = 0
			} else if character == '\\' && quote == '"' {
				escaped = true
			} else {
				word.WriteRune(character)
			}
			continue
		}
		switch character {
		case ' ', '\t':
			flush()
		case '\'', '"':
			quote = character
			started = true
		case '\\':
			escaped = true
			started = true
		case '|', '&', ';', '<', '>':
			return nil, ErrInvalidLine
		default:
			word.WriteRune(character)
			started = true
		}
	}
	if escaped || quote != 0 {
		return nil, ErrInvalidLine
	}
	flush()
	return arguments, nil
}
