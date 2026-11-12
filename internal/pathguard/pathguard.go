package pathguard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// The error texts never contain a path, because a path can hold a secret.
var (
	ErrInvalidRoot    = errors.New("the folder is not usable")
	ErrInvalidPath    = errors.New("the path is not valid")
	ErrOutsideRoot    = errors.New("the path is outside the allowed folder")
	ErrFoldersOverlap = errors.New("the output folder overlaps the source folder")
)

type Root struct {
	directory string
}

func NewRoot(directory string) (*Root, error) {
	resolved, err := resolveExisting(directory)
	if err != nil {
		return nil, ErrInvalidRoot
	}

	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return nil, ErrInvalidRoot
	}

	return &Root{directory: resolved}, nil
}

func (root *Root) Resolve(relativePath string) (string, error) {
	if relativePath == "" {
		relativePath = "."
	}
	if strings.ContainsRune(relativePath, 0) || filepath.IsAbs(relativePath) {
		return "", ErrInvalidPath
	}

	joined := filepath.Join(root.directory, relativePath)
	if !isInside(root.directory, joined) {
		return "", ErrOutsideRoot
	}

	resolved, err := filepath.EvalSymlinks(joined)
	if err != nil {
		return "", ErrInvalidPath
	}
	if !isInside(root.directory, resolved) {
		return "", ErrOutsideRoot
	}

	return resolved, nil
}

func (root *Root) Relative(resolvedPath string) string {
	relative, err := filepath.Rel(root.directory, resolvedPath)
	if err != nil {
		return ""
	}

	return filepath.ToSlash(relative)
}

func CheckOutputFolder(sourceDirectory, outputDirectory string) error {
	source, err := resolveLoosely(sourceDirectory)
	if err != nil {
		return err
	}
	output, err := resolveLoosely(outputDirectory)
	if err != nil {
		return err
	}

	if isInside(source, output) || isInside(output, source) {
		return ErrFoldersOverlap
	}

	return nil
}

func resolveExisting(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	return filepath.EvalSymlinks(absolute)
}

// resolveLoosely follows symlinks for the part of the path that exists, and keeps
// the rest as it is. The output folder may not exist yet.
func resolveLoosely(path string) (string, error) {
	current, err := filepath.Abs(path)
	if err != nil {
		return "", ErrInvalidPath
	}

	remainder := ""
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			return filepath.Join(resolved, remainder), nil
		}

		// Something is there but can not be followed, like a symlink that points nowhere.
		if _, lstatErr := os.Lstat(current); lstatErr == nil {
			return "", ErrInvalidPath
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", ErrInvalidPath
		}
		remainder = filepath.Join(filepath.Base(current), remainder)
		current = parent
	}
}

func isInside(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}

	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
