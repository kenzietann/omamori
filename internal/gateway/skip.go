package gateway

import "strings"

// These folders hold the code of other people, or the history of the project, and these files hold
// hashes and file lists that other tools write. Long hash strings look like phone numbers and My Numbers
// by chance, so a scan of them fills a report with false findings and hides the real ones.
// The report says that they are skipped. A secret that is committed into them is not found.
var (
	skippedFolders = map[string]bool{
		".git": true, "node_modules": true, "vendor": true, "__pycache__": true, ".venv": true, "venv": true,
		// Code of other projects and their caches. Thousands of files that are not the project's own would fill
		// the file budget of a scan before the project's own folders are reached.
		"Pods": true, "SourcePackages": true, "DerivedData": true, "Carthage": true, "bower_components": true,
		"site-packages": true, "jspm_packages": true, ".yarn": true, ".pnpm-store": true, ".angular": true,
		".parcel-cache": true, ".turbo": true, ".gradle": true,
	}
	// Folders of AI coding tools. Their skills and plugins were written by other people.
	toolFolders       = map[string]bool{".agents": true, ".claude": true, ".codex": true, ".gemini": true, ".cursor": true, ".windsurf": true}
	toolPluginFolders = map[string]bool{"skills": true, "plugins": true, "extensions": true, "marketplace": true}
	skippedFiles      = map[string]bool{
		"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "go.sum": true,
		"Cargo.lock": true, "composer.lock": true, "poetry.lock": true, "Gemfile.lock": true,
	}
)

const skippedFileSuffix = ".tsbuildinfo"

// skippedEntry says whether a walk leaves out an entry. A file called .git is a pointer to the
// folder of a git work tree, so it is left out too.
func skippedEntry(name, parent string, isDir bool) bool {
	if name == ".git" {
		return true
	}
	if isDir {
		return skippedFolders[name] || toolPluginFolders[name] && toolFolders[parent]
	}

	return skippedFiles[name] || strings.HasSuffix(name, skippedFileSuffix)
}
