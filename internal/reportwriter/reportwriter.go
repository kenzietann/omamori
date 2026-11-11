package reportwriter

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/kenzietann/omamori/internal/pathguard"
)

const (
	maxContentBytes = 5 << 20
	maxLogBytes     = 50 << 20
)

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

type Appender struct {
	file    *os.File
	written int
	limit   int
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

// NewRun reserves a new folder for one run, away from every input path.
// Creating the folder is exclusive, so simultaneous runs cannot share it.
func NewRun(sourceDirectories []string, outputDirectory string) (*Writer, error) {
	for _, source := range sourceDirectories {
		if err := pathguard.CheckOutputFolder(source, outputDirectory); err != nil {
			return nil, err
		}
	}
	writer, err := NewFolder(outputDirectory)
	if err != nil {
		return nil, err
	}
	for _, source := range sourceDirectories {
		if err := pathguard.CheckOutputFolder(source, writer.directory); err != nil {
			return nil, err
		}
	}

	return writer, nil
}

// NewFolder makes a writer for a folder that does not exist yet. It is for output that has no source folder
// to stay away from. An existing folder is refused, so nothing in it can be written over.
func NewFolder(outputDirectory string) (*Writer, error) {
	if err := os.MkdirAll(filepath.Dir(outputDirectory), 0o700); err != nil {
		return nil, ErrOutputFolder
	}
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, ErrExists
		}

		return nil, ErrOutputFolder
	}
	resolved, err := filepath.EvalSymlinks(outputDirectory)
	if err != nil {
		return nil, ErrOutputFolder
	}

	return &Writer{directory: resolved}, nil
}

// createFile makes O_EXCL do the work: the system refuses an existing file, and a
// symlink that stands in the place of the file, so nothing is ever overwritten.
func (writer *Writer) createFile(name string, extraFlags int) (*os.File, error) {
	if !validName.MatchString(name) {
		return nil, ErrInvalidName
	}

	file, err := os.OpenFile(filepath.Join(writer.directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|extraFlags, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, ErrExists
		}
		return nil, ErrWriteFailed
	}

	return file, nil
}

func (writer *Writer) Write(name, content string) error {
	if len(content) > maxContentBytes {
		return ErrTooLarge
	}

	file, err := writer.createFile(name, 0)
	if err != nil {
		return err
	}

	_, writeErr := file.WriteString(content)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return ErrWriteFailed
	}

	return nil
}

func (writer *Writer) Open(name string) (*Appender, error) {
	file, err := writer.createFile(name, os.O_APPEND)
	if err != nil {
		return nil, err
	}

	return &Appender{file: file, limit: maxLogBytes}, nil
}

func (appender *Appender) Append(text string) error {
	if len(text) > maxContentBytes || appender.written+len(text) > appender.limit {
		return ErrTooLarge
	}

	if _, err := appender.file.WriteString(text); err != nil {
		return ErrWriteFailed
	}
	appender.written += len(text)

	return nil
}

func (appender *Appender) Close() error {
	if err := appender.file.Close(); err != nil {
		return ErrWriteFailed
	}

	return nil
}
