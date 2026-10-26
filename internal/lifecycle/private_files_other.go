//go:build !unix

package lifecycle

import "os"

func preservePrivateOwner(_ *os.File, _ os.FileInfo) error { return nil }
