package gateway

import "strings"

// These folders hold the code of other people, or the history of the project, and these files hold
// hashes and file lists that other tools write. Long hash strings look like phone numbers and My Numbers
// by chance, so a scan of them fills a report with false findings and hides the real ones.
// The report says that they are skipped. A secret that is committed into them is not found.
var (
	skippedFolders = map[string]bool{
		".git": true, "node_modules": true, "vendor": true, "__pycache__": true, ".venv": true, "venv": true,
	}
	skippedFiles = map[string]bool{
		"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "go.sum": true,
		"Cargo.lock": true, "composer.lock": true, "poetry.lock": true, "Gemfile.lock": true,
	}
)

const skippedFileSuffix = ".tsbuildinfo"

// skippedEntry says whether a walk leaves out an entry. A file called .git is a pointer to the
// folder of a git work tree, so it is left out too.
func skippedEntry(name string, isDir bool) bool {
	if name == ".git" {
		return true
	}
	if isDir {
		return skippedFolders[name]
	}

	return skippedFiles[name] || strings.HasSuffix(name, skippedFileSuffix)
}
