package reportwriter

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/pathguard"
)

func makeWriter(t *testing.T) (writer *Writer, outputDirectory, workspace string) {
	t.Helper()

	workspace = t.TempDir()
	sourceDirectory := filepath.Join(workspace, "project")
	outputDirectory = filepath.Join(workspace, "reports")

	if err := os.MkdirAll(sourceDirectory, 0o755); err != nil {
		t.Fatal(err)
	}

	writer, err := New(sourceDirectory, outputDirectory)
	if err != nil {
		t.Fatal(err)
	}

	return writer, outputDirectory, workspace
}

func TestWriteCreatesANewFile(t *testing.T) {
	writer, outputDirectory, _ := makeWriter(t)

	if err := writer.Write("report.md", "first report"); err != nil {
		t.Fatal(err)
	}

	gotContent, err := os.ReadFile(filepath.Join(outputDirectory, "report.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(gotContent) != "first report" {
		t.Errorf("file content = %q, want %q", gotContent, "first report")
	}
}

func TestWriteNeverOverwrites(t *testing.T) {
	writer, outputDirectory, _ := makeWriter(t)

	if err := writer.Write("report.md", "first report"); err != nil {
		t.Fatal(err)
	}

	err := writer.Write("report.md", "second report")
	if !errors.Is(err, ErrExists) {
		t.Errorf("second Write error = %v, want %v", err, ErrExists)
	}

	gotContent, _ := os.ReadFile(filepath.Join(outputDirectory, "report.md"))
	if string(gotContent) != "first report" {
		t.Errorf("the existing file changed to %q", gotContent)
	}
}

func TestWriteRefusesBadNames(t *testing.T) {
	writer, _, _ := makeWriter(t)

	testCases := []struct {
		name      string
		inputName string
	}{
		{"empty", ""},
		{"parent folder", "../report.md"},
		{"sub folder", "sub/report.md"},
		{"absolute path", "/tmp/report.md"},
		{"backslash", `sub\report.md`},
		{"starts with a dot", ".hidden"},
		{"only dots", ".."},
		{"space", "my report.md"},
		{"NUL byte", "report\x00.md"},
		{"too long", strings.Repeat("a", 101)},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := writer.Write(testCase.inputName, "content")

			if !errors.Is(err, ErrInvalidName) {
				t.Errorf("Write(%q) error = %v, want %v", testCase.inputName, err, ErrInvalidName)
			}
		})
	}
}

func TestWriteRefusesASymlinkInTheOutputFolder(t *testing.T) {
	writer, outputDirectory, workspace := makeWriter(t)

	target := filepath.Join(workspace, "important.txt")
	if err := os.WriteFile(target, []byte("do not touch"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(outputDirectory, "report.md")); err != nil {
		t.Fatal(err)
	}

	if err := writer.Write("report.md", "overwritten"); err == nil {
		t.Error("Write through a symlink succeeded")
	}

	gotContent, _ := os.ReadFile(target)
	if string(gotContent) != "do not touch" {
		t.Errorf("the file behind the symlink changed to %q", gotContent)
	}
}

func TestWriteRefusesTooMuchContent(t *testing.T) {
	writer, _, _ := makeWriter(t)

	err := writer.Write("big.md", strings.Repeat("a", maxContentBytes+1))

	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("Write error = %v, want %v", err, ErrTooLarge)
	}
}

func TestNewRefusesOverlappingFolders(t *testing.T) {
	workspace := t.TempDir()
	sourceDirectory := filepath.Join(workspace, "project")
	if err := os.MkdirAll(sourceDirectory, 0o755); err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name            string
		outputDirectory string
	}{
		{"same folder", sourceDirectory},
		{"inside the project", filepath.Join(sourceDirectory, "reports")},
		{"contains the project", workspace},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := New(sourceDirectory, testCase.outputDirectory)

			if !errors.Is(err, pathguard.ErrFoldersOverlap) {
				t.Errorf("New error = %v, want %v", err, pathguard.ErrFoldersOverlap)
			}
		})
	}

	if _, err := os.Stat(filepath.Join(sourceDirectory, "reports")); err == nil {
		t.Error("a refused output folder was still created inside the project")
	}
}
