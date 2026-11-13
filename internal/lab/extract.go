package lab

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"time"
)

const (
	maxExtractFile  = 256 << 20
	maxExtractTotal = 4 << 30
	maxExtractItems = 500_000
)

// Extract unpacks a tar stream into a new folder. The stream comes from a server on which an attacker had a
// shell, so it is treated as hostile: names that leave the folder are refused, a link is made as a link and
// never followed (os.Root refuses any path through a link that leads outside), devices and hard links are not
// made, special permission bits are dropped, and sizes are limited. It gives the number of entries not kept.
func Extract(reader io.Reader, folder string) (int, error) {
	if err := os.Mkdir(folder, 0o700); err != nil {
		return 0, fmt.Errorf("%w: the evidence folder cannot be made", ErrFailed)
	}
	root, err := os.OpenRoot(folder)
	if err != nil {
		return 0, fmt.Errorf("%w: the evidence folder cannot be opened", ErrFailed)
	}
	defer root.Close()

	type stamp struct {
		name string
		when time.Time
	}
	var folders []stamp
	skipped, items := 0, 0
	var total int64
	archive := tar.NewReader(reader)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return skipped, fmt.Errorf("%w: the copy of web01 is broken", ErrFailed)
		}
		if items++; items > maxExtractItems {
			return skipped, fmt.Errorf("%w: the copy of web01 has too many files", ErrFailed)
		}
		name := path.Clean(header.Name)
		if name == "." {
			continue
		}
		if !fs.ValidPath(name) {
			skipped++
			continue
		}
		if dir := path.Dir(name); dir != "." {
			if err := root.MkdirAll(dir, 0o700); err != nil {
				skipped++
				continue
			}
		}
		mode := fs.FileMode(header.Mode).Perm() | 0o600
		switch header.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(name, 0o700); err != nil {
				skipped++
				continue
			}
			root.Chmod(name, mode|0o700)
			folders = append(folders, stamp{name, header.ModTime})
		case tar.TypeReg:
			if header.Size > maxExtractFile || total+header.Size > maxExtractTotal {
				return skipped, fmt.Errorf("%w: the copy of web01 is too large", ErrFailed)
			}
			file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				skipped++
				continue
			}
			written, copyErr := io.Copy(file, io.LimitReader(archive, header.Size))
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil || written != header.Size {
				return skipped, fmt.Errorf("%w: a file of the copy could not be written", ErrFailed)
			}
			total += written
			root.Chmod(name, mode)
			root.Chtimes(name, header.ModTime, header.ModTime)
		case tar.TypeSymlink:
			// The target is kept as text. It is never opened here, and forensics does not follow links.
			if err := root.Symlink(header.Linkname, name); err != nil {
				skipped++
			}
		default:
			skipped++
		}
	}
	// The times of folders are set last, since writing into a folder changes its time.
	for index := len(folders) - 1; index >= 0; index-- {
		root.Chtimes(folders[index].name, folders[index].when, folders[index].when)
	}

	return skipped, nil
}
