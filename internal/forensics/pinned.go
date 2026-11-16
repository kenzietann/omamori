package forensics

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	// KindProgram is a program that a launchd item starts. It is hashed, not read, so that a known-good entry
	// for the item stops fitting when the program is changed.
	KindProgram = "launchd_program"
	// KindHostName is the file that names the machine.
	KindHostName = "hostname"

	maxProgramBytes    = 256 << 20
	maxProgramsPerItem = 4
	maxHostNameBytes   = 1 << 20
)

// programPath finds absolute paths in a command: the program and the files that its arguments name, like the
// program inside "/usr/bin/osascript -e 'do shell script \"/Users/a/.x/agent\"'".
var programPath = regexp.MustCompile(`(?:^|[\s"'=(])(/[^\s"'();|&<>\\$` + "`" + `]{1,1000})`)

// hashFile hashes one file of the evidence without following a link, and records it in the manifest. A file
// that was read before keeps its entry. keep is how many of the first bytes to give back (0 for none).
func (c *collector) hashFile(name, kind string, limit int64, keep int) (digest string, head []byte, ok bool) {
	recorded := c.seen[name]
	for _, entry := range c.result.Manifest.Entries {
		if entry.Path == name {
			if keep == 0 {
				return entry.SHA256, nil, entry.SHA256 != ""
			}
			// It is read again for its content, and keeps the entry that it has.
			recorded = true
			break
		}
	}
	info, err := c.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return "", nil, false
	}
	if info.Size() > limit {
		c.skip(name, "too big to hash for a known-good entry")
		return "", nil, false
	}
	file, err := c.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		c.skip(name, "cannot be opened")
		return "", nil, false
	}
	defer file.Close()
	if info, err = file.Stat(); err != nil || !info.Mode().IsRegular() {
		return "", nil, false
	}
	hasher := sha256.New()
	var kept bytes.Buffer
	reader := io.TeeReader(io.LimitReader(file, limit+1), hasher)
	if keep > 0 {
		if _, err := io.CopyN(&kept, reader, int64(keep)); err != nil && err != io.EOF {
			return "", nil, false
		}
	}
	if _, err := io.Copy(io.Discard, reader); err != nil {
		c.skip(name, "could not be read to its end")
		return "", nil, false
	}
	digest = hex.EncodeToString(hasher.Sum(nil))
	if !recorded && len(c.result.Manifest.Entries) < maxEntries {
		c.seen[name] = true
		c.result.Manifest.Entries = append(c.result.Manifest.Entries, Entry{
			Path: name, Kind: kind, Size: info.Size(), Mode: info.Mode().String(), Modified: info.ModTime().UTC().Format(time.RFC3339), SHA256: digest,
		})
	}

	return digest, kept.Bytes(), true
}

// programs gives the hashes of the programs and files that a command names, as "path=sha256" joined by "; ".
// A path that is not a file of the evidence is "missing", so a program that appears later changes the value.
func (c *collector) programs(command string) string {
	seen := map[string]bool{}
	var parts []string
	for _, match := range programPath.FindAllStringSubmatch(command, -1) {
		absolute := strings.TrimRight(match[1], ".,:")
		name := strings.TrimPrefix(path.Clean(absolute), "/")
		if seen[name] || !fs.ValidPath(name) || name == "." {
			continue
		}
		seen[name] = true
		if info, err := c.root.Lstat(name); err == nil && info.IsDir() {
			// A folder (a working directory, a data folder) is not a program.
			continue
		}
		digest, _, ok := c.hashFile(name, KindProgram, maxProgramBytes, 0)
		if !ok {
			digest = "missing"
		}
		parts = append(parts, "/"+name+"="+digest)
		if len(parts) == maxProgramsPerItem {
			break
		}
	}
	sort.Strings(parts)

	return strings.Join(parts, "; ")
}

// hostName reads the name of the machine: /etc/hostname on Linux, the settings of the system on a Mac.
func (c *collector) hostName() string {
	if c.product != ProductMacOS {
		_, data, ok := c.hashFile("etc/hostname", KindHostName, maxHostNameBytes, 256)
		if !ok {
			return ""
		}
		line, _, _ := strings.Cut(string(data), "\n")

		return tidy(line, 255)
	}
	_, data, ok := c.hashFile("Library/Preferences/SystemConfiguration/preferences.plist", KindHostName, maxHostNameBytes, maxHostNameBytes)
	if !ok {
		return ""
	}
	values, err := readPlist(data)
	if err != nil {
		return ""
	}
	system, _ := values["System"].(map[string]any)
	inner, _ := system["System"].(map[string]any)
	network, _ := system["Network"].(map[string]any)
	names, _ := network["HostNames"].(map[string]any)
	for _, candidate := range []any{inner["HostName"], names["LocalHostName"], inner["ComputerName"]} {
		if text, isText := candidate.(string); isText && strings.TrimSpace(text) != "" {
			return tidy(text, 255)
		}
	}

	return ""
}
