package pathguard

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t testing.TB, path string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("fake content"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func makeSymlink(t testing.TB, target, link string) {
	t.Helper()

	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// makeWorkspace returns a folder that holds "project" and "outside" side by side.
func makeWorkspace(t testing.TB) (workspace, project, outside string) {
	t.Helper()

	workspace = t.TempDir()
	project = filepath.Join(workspace, "project")
	outside = filepath.Join(workspace, "outside")

	writeFile(t, filepath.Join(project, "notes.txt"))
	writeFile(t, filepath.Join(project, "sub", "inner.txt"))
	writeFile(t, filepath.Join(outside, "secret.txt"))

	makeSymlink(t, filepath.Join(outside, "secret.txt"), filepath.Join(project, "escape-file"))
	makeSymlink(t, outside, filepath.Join(project, "escape-dir"))
	makeSymlink(t, "notes.txt", filepath.Join(project, "inside-link"))

	return workspace, project, outside
}

func TestResolve(t *testing.T) {
	_, project, outside := makeWorkspace(t)

	root, err := NewRoot(project)
	if err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name         string
		inputPath    string
		wantError    error
		wantRelative string
	}{
		{"file", "notes.txt", nil, "notes.txt"},
		{"nested file", "sub/inner.txt", nil, "sub/inner.txt"},
		{"root itself", ".", nil, "."},
		{"empty path means the root", "", nil, "."},
		{"dot segments that stay inside", "sub/../notes.txt", nil, "notes.txt"},
		{"symlink that stays inside", "inside-link", nil, "notes.txt"},
		{"parent folder", "..", ErrOutsideRoot, ""},
		{"file in the parent folder", "../outside/secret.txt", ErrOutsideRoot, ""},
		{"escape through dot segments", "sub/../../outside/secret.txt", ErrOutsideRoot, ""},
		{"missing file in the parent folder", "../outside/missing.txt", ErrOutsideRoot, ""},
		{"absolute path", filepath.Join(outside, "secret.txt"), ErrInvalidPath, ""},
		{"NUL byte", "notes\x00.txt", ErrInvalidPath, ""},
		{"symlink to an outside file", "escape-file", ErrOutsideRoot, ""},
		{"file behind a symlink to an outside folder", "escape-dir/secret.txt", ErrOutsideRoot, ""},
		{"missing file", "missing.txt", ErrInvalidPath, ""},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotPath, err := root.Resolve(testCase.inputPath)

			if !errors.Is(err, testCase.wantError) {
				t.Fatalf("Resolve(%q) error = %v, want %v", testCase.inputPath, err, testCase.wantError)
			}
			if err != nil {
				if testCase.inputPath != "" && strings.Contains(err.Error(), testCase.inputPath) {
					t.Errorf("the error text contains the path: %q", err.Error())
				}
				return
			}
			if gotRelative := root.Relative(gotPath); gotRelative != testCase.wantRelative {
				t.Errorf("Relative(Resolve(%q)) = %q, want %q", testCase.inputPath, gotRelative, testCase.wantRelative)
			}
		})
	}
}

func TestNewRoot(t *testing.T) {
	_, project, _ := makeWorkspace(t)

	testCases := []struct {
		name           string
		inputDirectory string
		wantError      error
	}{
		{"folder", project, nil},
		{"missing folder", filepath.Join(project, "missing"), ErrInvalidRoot},
		{"a file, not a folder", filepath.Join(project, "notes.txt"), ErrInvalidRoot},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := NewRoot(testCase.inputDirectory)

			if !errors.Is(err, testCase.wantError) {
				t.Errorf("NewRoot error = %v, want %v", err, testCase.wantError)
			}
		})
	}
}

func TestCheckOutputFolder(t *testing.T) {
	workspace, project, _ := makeWorkspace(t)

	makeSymlink(t, project, filepath.Join(workspace, "link-to-project"))
	makeSymlink(t, filepath.Join(project, "missing"), filepath.Join(workspace, "dangling"))

	testCases := []struct {
		name            string
		outputDirectory string
		wantError       error
	}{
		{"same folder", project, ErrFoldersOverlap},
		{"inside the project", filepath.Join(project, "sub"), ErrFoldersOverlap},
		{"inside the project, not created yet", filepath.Join(project, "new", "deeper"), ErrFoldersOverlap},
		{"contains the project", workspace, ErrFoldersOverlap},
		{"symlink to the project", filepath.Join(workspace, "link-to-project"), ErrFoldersOverlap},
		{"new folder behind a symlink to the project", filepath.Join(workspace, "link-to-project", "new"), ErrFoldersOverlap},
		{"dangling symlink", filepath.Join(workspace, "dangling"), ErrInvalidPath},
		{"sibling folder", filepath.Join(workspace, "reports"), nil},
		{"sibling folder, not created yet", filepath.Join(workspace, "new", "reports"), nil},
		{"sibling with a similar name", filepath.Join(workspace, "project-reports"), nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			err := CheckOutputFolder(project, testCase.outputDirectory)

			if !errors.Is(err, testCase.wantError) {
				t.Errorf("CheckOutputFolder error = %v, want %v", err, testCase.wantError)
			}
		})
	}
}

func FuzzResolve(f *testing.F) {
	_, project, _ := makeWorkspace(f)

	root, err := NewRoot(project)
	if err != nil {
		f.Fatal(err)
	}

	f.Add("notes.txt")
	f.Add("../outside/secret.txt")
	f.Add("escape-dir/secret.txt")
	f.Add("sub/../../outside")
	f.Add("")

	f.Fuzz(func(t *testing.T, inputPath string) {
		gotPath, err := root.Resolve(inputPath)

		if err == nil && !isInside(root.directory, gotPath) {
			t.Fatalf("Resolve returned a path outside the project for %q", inputPath)
		}
	})
}
