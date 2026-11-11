package rules

import (
	"os"
	"path/filepath"
)

func writeFile(folder, name, text string) error {
	path := filepath.Join(folder, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(text), 0o600)
}
