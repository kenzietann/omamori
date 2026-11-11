package tui

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

func TestNoOtherPackageImportsTheUI(t *testing.T) {
	const tuiPackage = "github.com/kenzietann/omamori/internal/tui"

	checked := 0
	err := filepath.WalkDir(filepath.Join("..", ".."), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && (entry.Name() == ".git" || entry.Name() == "testdata") {
			return fs.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		relative, err := filepath.Rel(filepath.Join("..", ".."), path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if strings.HasPrefix(relative, "internal/tui/") || strings.HasPrefix(relative, "cmd/") {
			return nil
		}

		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		checked++

		for _, imported := range parsed.Imports {
			importPath := strings.Trim(imported.Path.Value, `"`)
			if importPath == tuiPackage || strings.HasPrefix(importPath, "github.com/charmbracelet/") {
				t.Errorf("%s imports %s, but only cmd/ may import the UI", relative, importPath)
			}
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 20 {
		t.Errorf("only %d Go files were checked, the walk is wrong", checked)
	}
}
