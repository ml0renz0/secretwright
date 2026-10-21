package cli

import (
	"context"
	"io"
)

func RunWithInput(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, version string) int {
	return 1
}
