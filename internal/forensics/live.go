package forensics

import (
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// ReadPlaces are the folders of a system that a run reads, as paths relative to the top of the system: the
// folders of the artifact patterns and the folders that the file rules look at. On a running system, the top
// of the system is "/", and everything is inside it, so "the report must be outside the evidence" cannot be
// asked of the whole tree. It is asked of these places instead: a report in one of them would change the
// evidence, and the next run would read the report as if it were part of the system.
func ReadPlaces() []string {
	seen := map[string]bool{}
	for _, folder := range scanFolders {
		seen[folder] = true
	}
	for _, current := range patterns {
		var kept []string
		for _, part := range strings.Split(current.glob, "/") {
			if strings.Contains(part, "*") {
				break
			}
			kept = append(kept, part)
		}
		folder := path.Join(kept...)
		if folder == current.glob {
			// A pattern without a wildcard names one file, and its folder is what is read.
			folder = path.Dir(folder)
		}
		if folder != "." && folder != "" {
			seen[folder] = true
		}
	}
	places := make([]string, 0, len(seen))
	for folder := range seen {
		places = append(places, folder)
	}
	sort.Strings(places)

	return places
}

// IsSystemRoot reports whether a folder is the top of the file system of the machine that runs this, which
// is how a running system is looked at. The path is resolved first, so a link to / counts as /.
func IsSystemRoot(folder string) bool {
	absolute, err := filepath.Abs(folder)
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return false
	}

	return filepath.Dir(resolved) == resolved
}

// LivePlaces gives the places of a running system as absolute paths, for the checks that keep a report, a
// database or a recording out of the evidence.
func LivePlaces(root string) []string {
	places := ReadPlaces()
	absolute := make([]string, len(places))
	for i, place := range places {
		absolute[i] = filepath.Join(root, filepath.FromSlash(place))
	}

	return absolute
}
