package reportwriter

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/kenzietann/omamori/internal/pathguard"
)

const maxContentBytes = 5 << 20

var (
	ErrInvalidName  = errors.New("the report name is not valid")
	ErrExists       = errors.New("a file with this name already exists")
	ErrTooLarge     = errors.New("the report is too large")
	ErrWriteFailed  = errors.New("the report could not be written")
	ErrOutputFolder = errors.New("the output folder is not usable")
)

var validName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

type Writer struct {
	directory string
}

func New(sourceDirectory, outputDirectory string) (*Writer, error) {
	if err := pathguard.CheckOutputFolder(sourceDirectory, outputDirectory); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(outputDirectory, 0o700); err != nil {
		return nil, ErrOutputFolder
	}
	resolved, err := filepath.EvalSymlinks(outputDirectory)
	if err != nil {
		return nil, ErrOutputFolder
	}

	// Check again after the folder exists, because MkdirAll may have followed a symlink.
	if err := pathguard.CheckOutputFolder(sourceDirectory, resolved); err != nil {
		return nil, err
	}

	return &Writer{directory: resolved}, nil
}

func (writer *Writer) Write(name, content string) error {
	if !validName.MatchString(name) {
		return ErrInvalidName
	}
	if len(content) > maxContentBytes {
		return ErrTooLarge
	}

	// O_EXCL makes the system refuse an existing file, and a symlink that
	// stands in the place of the file, so nothing is ever overwritten.
	file, err := os.OpenFile(filepath.Join(writer.directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrExists
		}
		return ErrWriteFailed
	}

	_, writeErr := file.WriteString(content)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return ErrWriteFailed
	}

	return nil
}
