package shell

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

func isolatedTerminalState() *terminalEditor {
	return &terminalEditor{closed: make(chan struct{}), failed: make(chan struct{})}
}

func readPhysicalTerminalLine(t *testing.T, input *bufio.Reader) string {
	t.Helper()
	var line strings.Builder
	for {
		character, _, err := input.ReadRune()
		if err != nil {
			t.Fatalf("read physical terminal line: %v", err)
		}
		line.WriteRune(character)
		if character == '\n' {
			return line.String()
		}
	}
}

func TestTerminalInputRejectsNULAndMalformedUTF8WithoutSubmittingAPrefix(t *testing.T) {
	for _, malformed := range [][]byte{{0}, {0xff}, {0xc3}} {
		editor := isolatedTerminalState()
		physical := append([]byte("pwd "), malformed...)
		physical = append(physical, []byte("private-input-marker\npwd\n")...)
		input := &terminalInput{editor: editor, reader: bufio.NewReader(bytes.NewReader(physical))}
		decoded := bufio.NewReader(input)
		line := readPhysicalTerminalLine(t, decoded)
		if !editor.invalid || strings.ContainsRune(line, 0) || !strings.HasSuffix(line, "private-input-marker\n") {
			t.Error("malformed terminal bytes became EOF or detached a valid command prefix")
		}
		if retained, _, discard := editor.limitLine([]rune(line), len([]rune(line)), '\n'); len(retained) != 0 || !discard {
			t.Error("an invalid physical terminal line retained an executable prefix")
		}
		// ReadLine resets the physical-line flag before the next prompt. Buffered
		// input must not transfer the previous line's invalid state to that prompt.
		editor.invalid = false
		if next := readPhysicalTerminalLine(t, decoded); next != "pwd\n" || editor.invalid {
			t.Error("terminal decoder contaminated the following valid physical line")
		}
	}
}

func TestTerminalInputAssociatesMalformedBytesWithTheirOwnPhysicalLine(t *testing.T) {
	editor := isolatedTerminalState()
	input := &terminalInput{editor: editor, reader: bufio.NewReader(bytes.NewReader([]byte("pwd\nls \xff\n")))}
	decoded := bufio.NewReader(input)
	if first := readPhysicalTerminalLine(t, decoded); first != "pwd\n" || editor.invalid {
		t.Error("a pasted later line invalidated an earlier valid line")
	}
	readPhysicalTerminalLine(t, decoded)
	if !editor.invalid {
		t.Error("malformed bytes in the second pasted line were not rejected")
	}
}

func TestTerminalInputPreservesValidUnicodeIncludingReplacementRune(t *testing.T) {
	editor := isolatedTerminalState()
	text := "ls /secret/área/東京/\ufffd\n"
	input := &terminalInput{editor: editor, reader: bufio.NewReader(strings.NewReader(text))}
	decoded := bufio.NewReader(input)
	if got := readPhysicalTerminalLine(t, decoded); got != text || editor.invalid {
		t.Error("terminal decoder confused valid Unicode with malformed bytes")
	}
	if _, _, err := decoded.ReadRune(); !errors.Is(err, io.EOF) {
		t.Error("terminal decoder did not preserve end of input")
	}
}

func TestTerminalLineLimitCountsUTF8BytesAndRetainsTheRejection(t *testing.T) {
	editor := isolatedTerminalState()
	atLimit := []rune(strings.Repeat("界", MaxLineBytes/utf8.RuneLen('界')))
	if _, _, discard := editor.limitLine(atLimit, len(atLimit), '界'); discard || editor.long {
		t.Error("valid Unicode input below the byte limit was rejected")
	}
	overLimit := append(atLimit, '界')
	if line, position, discard := editor.limitLine(overLimit, len(overLimit), '界'); len(line) != 0 || position != 0 || !discard || !editor.long {
		t.Error("terminal line was not rejected as a whole after exceeding its byte limit")
	}
	if line, _, discard := editor.limitLine([]rune("pwd"), 3, '\n'); len(line) != 0 || !discard {
		t.Error("trimming a rejected line made its prefix executable again")
	}
}

type failingTerminalOutput struct {
	short bool
}

func (output failingTerminalOutput) Write(value []byte) (int, error) {
	if output.short {
		return len(value) - 1, nil
	}
	return 0, errors.New("private-writer-marker")
}

func TestTerminalWriterMakesShortAndFailedWritesVisibleWithoutPrivateErrors(t *testing.T) {
	for _, short := range []bool{false, true} {
		editor := isolatedTerminalState()
		writer := terminalWriter{editor: editor, target: failingTerminalOutput{short: short}}
		if _, err := writer.Write([]byte("prompt")); !errors.Is(err, errTerminalOutput) || strings.Contains(err.Error(), "private-writer-marker") {
			t.Error("terminal output failure was ignored or exposed an underlying error")
		}
		if !errors.Is(editor.failure(), errTerminalOutput) {
			t.Error("terminal editor did not retain the output failure")
		}
		select {
		case <-editor.failed:
		default:
			t.Error("terminal output failure did not release a blocked reader")
		}
	}
}

func TestTerminalCompletionDisplaysSuffixesWithoutAWidePrefixOffset(t *testing.T) {
	line := []rune("ls /secret/東京")
	want := [][]rune{[]rune("alpha/"), []rune("beta ")}
	leftMenu := 0
	complete := terminalCompleter{
		complete: func(received []rune, position int) ([][]rune, int) {
			if !reflect.DeepEqual(received, line) || position != len(line) {
				t.Error("terminal adapter changed the completion query or rune cursor")
			}
			return want, len([]rune("/secret/東京"))
		},
		width: func() int {
			return 40
		},
		leaveMenu: func() {
			leftMenu++
		},
	}
	got, offset := complete.Do(line, len(line))
	if !reflect.DeepEqual(got, want) || offset != 0 || leftMenu != 0 {
		t.Error("terminal menu mixed a Unicode rune prefix with display-column padding")
	}
}

func TestTerminalCompletionInsertsAUniqueSuffixInFullEvenOnANarrowTerminal(t *testing.T) {
	want := []rune(strings.Repeat("東京", 40) + "/")
	leftMenu := 0
	complete := terminalCompleter{
		complete: func([]rune, int) ([][]rune, int) {
			return [][]rune{want}, 4
		},
		width: func() int {
			return 2
		},
		leaveMenu: func() {
			leftMenu++
		},
	}
	got, offset := complete.Do([]rune("cd /secret/"), len([]rune("cd /secret/")))
	if len(got) != 1 || !reflect.DeepEqual(got[0], want) || offset != 0 || leftMenu != 1 {
		t.Error("unique completion was truncated or retained a menu that cannot display it")
	}
}

func TestTerminalCompletionUsesDisplayWidthAndOnlyExpandsARealCommonPrefix(t *testing.T) {
	for _, test := range []struct {
		name       string
		width      int
		candidates []string
		want       []string
		leave      bool
	}{
		{name: "wide characters", width: 4, candidates: []string{"界甲", "界乙"}, want: []string{"界"}, leave: true},
		{name: "no shared prefix", width: 4, candidates: []string{"東京", "京都"}},
		{name: "long shared prefix", width: 6, candidates: []string{"abcdefghijkl-one/", "abcdefghijkl-two/"}, want: []string{"abcdefghijkl-"}, leave: true},
		{name: "fitting suffixes", width: 8, candidates: []string{"alpha/", "beta "}, want: []string{"alpha/", "beta "}},
		{name: "zero width", width: 0, candidates: []string{"alpha/", "beta "}},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := make([][]rune, len(test.candidates))
			for i, candidate := range test.candidates {
				values[i] = []rune(candidate)
			}
			leftMenu := 0
			complete := terminalCompleter{
				complete: func([]rune, int) ([][]rune, int) {
					return values, 8
				},
				width: func() int {
					return test.width
				},
				leaveMenu: func() {
					leftMenu++
				},
			}
			got, offset := complete.Do([]rune("ls /secret/"), len([]rune("ls /secret/")))
			stringsOfRunes := make([]string, 0, len(got))
			for _, candidate := range got {
				stringsOfRunes = append(stringsOfRunes, string(candidate))
			}
			if offset != 0 || len(stringsOfRunes) != len(test.want) {
				t.Fatal("unsafe terminal menu was retained or candidate text was partially selected")
			}
			for i, want := range test.want {
				if stringsOfRunes[i] != want {
					t.Error("terminal adapter fabricated or truncated candidate text instead of using a common prefix")
				}
			}
			if (leftMenu != 0) != test.leave {
				t.Error("terminal adapter did not leave selection mode before direct prefix insertion")
			}
		})
	}
}
