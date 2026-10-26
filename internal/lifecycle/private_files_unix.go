//go:build unix

package lifecycle

import (
	"os"
	"syscall"
)

func preservePrivateOwner(file *os.File, original os.FileInfo) error {
	owner, ok := original.Sys().(*syscall.Stat_t)
	if !ok { return ErrIO }
	current, err := file.Stat()
	if err != nil { return ErrIO }
	actual, ok := current.Sys().(*syscall.Stat_t)
	if !ok { return ErrIO }
	if owner.Uid != actual.Uid || owner.Gid != actual.Gid {
		if file.Chown(int(owner.Uid), int(owner.Gid)) != nil { return ErrIO }
	}
	current, err = file.Stat()
	if err != nil { return ErrIO }
	actual, ok = current.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != actual.Uid || owner.Gid != actual.Gid { return ErrIO }
	return nil
}
