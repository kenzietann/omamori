package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/filerules"
	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/rules"
)

const (
	KindScanned = "file_scan"

	ActionFileRule  = "file_rule_match"
	ActionKnownHash = "file_known_hash"
	FileRuleField   = "file_rule"

	maxScanFiles     = 20_000
	maxScanTotal     = 1 << 30
	maxScanFileBytes = 64 << 20
	maxScanDirectory = 5000
)

// scanFolders are the places that the file rules look at, in this order: the folders that everyone can write
// first, because tools of an attacker are found there most, then web pages, programs that were added by hand
// and settings, and the homes last. Homes can hold gigabytes of projects and data, and they must not use up
// the limit of the scan before the places of the system are looked at. The programs of the system
// (/usr/bin, /usr/lib) are not looked at.
var scanFolders = []string{
	"tmp", "var/tmp", "dev/shm", "var/www", "srv", "usr/share/nginx", "usr/local/bin", "usr/local/sbin", "opt",
	"etc", "var/spool/cron", "root", "home",
}

// notScanned are folders of downloaded packages and caches. They are big, and what is in them came from a
// package source. Each one that is passed over is named in the manifest.
var notScanned = map[string]bool{
	"node_modules": true, ".git": true, ".cache": true, "__pycache__": true, "site-packages": true,
	".venv": true, "venv": true, ".npm": true, ".rustup": true, ".cargo": true, ".m2": true, ".gradle": true,
}

// Files and folders with password hashes, private keys and credentials are never opened by the file rules:
// they are not read, not hashed and not named anywhere, not even as passed over.
var (
	secretFolders = map[string]bool{
		".ssh": true, ".gnupg": true, ".aws": true, ".azure": true, ".kube": true, ".docker": true, ".password-store": true,
		"gcloud": true, ".gcloud": true, "keyrings": true,
	}
	secretPaths = []string{"etc/ssh", "etc/ssl/private", "etc/pki", "etc/letsencrypt", "var/lib/sss"}
	secretNames = map[string]bool{
		"shadow": true, "shadow-": true, "gshadow": true, "gshadow-": true, "opasswd": true, "security-opasswd": true,
		".netrc": true, ".pgpass": true, ".git-credentials": true, ".my.cnf": true, ".npmrc": true, ".pypirc": true,
		".boto": true, ".s3cfg": true, "credentials": true, "id_rsa": true, "id_dsa": true, "id_ecdsa": true,
		"id_ed25519": true, "id_ecdsa_sk": true, "id_ed25519_sk": true,
	}
	secretEndings = []string{".key", ".pem", ".p12", ".pfx", ".kdbx", ".keystore", ".jks"}
)

func secretFolder(name string) bool {
	return secretFolders[path.Base(name)] || slices.Contains(secretPaths, name)
}

func secretFile(name string) bool {
	base := path.Base(name)
	if secretNames[base] || base == ".env" || strings.HasPrefix(base, ".env.") {
		return true
	}
	for _, ending := range secretEndings {
		if strings.HasSuffix(base, ending) {
			return true
		}
	}

	return false
}

// parsedKinds are the artifacts whose content becomes events and is looked at by the detection rules. The file
// rules pass over them, so that one line does not give two alerts.
var parsedKinds = map[string]bool{
	KindLog: true, KindCron: true, KindHistory: true, KindUnit: true, KindKeys: true, KindAccounts: true,
}

type scanner struct {
	files, bytes int
	tooBig       int
	full         bool
	entries      map[string]int
}

// scan looks at the files of the scan folders with the file rules, and for the hashes of the indicator list.
// Each file that is read is hashed into the manifest, like the other artifacts.
func (c *collector) scan() error {
	if c.options.FileRules == nil && c.options.Indicators.Len() == 0 {
		return nil
	}
	state := &scanner{entries: map[string]int{}}
	for index, entry := range c.result.Manifest.Entries {
		state.entries[entry.Path] = index
	}
	for _, folder := range scanFolders {
		if err := c.walk(folder, state); err != nil {
			return err
		}
		if state.full {
			break
		}
	}
	if state.full {
		c.skip("file scan", fmt.Sprintf("the file rules stopped after %d files or %d MB; the rest of the folders were not looked at", state.files, state.bytes>>20))
	}
	if state.tooBig > 0 {
		c.skip("file scan", fmt.Sprintf("%d files over %d MB were not looked at by the file rules", state.tooBig, maxScanFileBytes>>20))
	}

	return nil
}

func (c *collector) walk(folder string, state *scanner) error {
	info, err := c.root.Lstat(folder)
	if err != nil || !info.IsDir() {
		return nil
	}
	directory, err := c.root.Open(folder)
	if err != nil {
		c.skip(folder, "the folder cannot be opened for the file rules")
		return nil
	}
	entries, _ := directory.ReadDir(maxScanDirectory + 1)
	directory.Close()
	if len(entries) > maxScanDirectory {
		c.skip(folder, "the folder has too many entries, the file rules looked at some of them")
		entries = entries[:maxScanDirectory]
	}
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })

	for _, entry := range entries {
		if state.full {
			return nil
		}
		name := path.Join(folder, entry.Name())
		switch kind := entry.Type(); {
		case kind.IsDir() && secretFolder(name), !kind.IsDir() && secretFile(name):
			continue
		case kind.IsDir():
			if notScanned[entry.Name()] {
				c.skip(name, "a folder of packages or a cache, not looked at by the file rules")
				continue
			}
			if err := c.walk(name, state); err != nil {
				return err
			}
		case kind.IsRegular():
			if err := c.scanFile(name, state); err != nil {
				return err
			}
		}
		// Links, devices, sockets and pipes are passed over. A link is never followed.
	}

	return nil
}

func (c *collector) scanFile(name string, state *scanner) error {
	index, known := state.entries[name]
	if known && parsedKinds[c.result.Manifest.Entries[index].Kind] {
		return nil
	}
	info, err := c.root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return nil
	}
	if info.Size() > maxScanFileBytes {
		state.tooBig++
		return nil
	}
	if state.files >= maxScanFiles || state.bytes+int(info.Size()) > maxScanTotal {
		state.full = true
		return nil
	}
	if !known && len(c.result.Manifest.Entries) >= maxEntries {
		return ErrTooBig
	}
	file, err := c.root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		c.skip(name, "cannot be opened by the file rules")
		return nil
	}
	defer file.Close()
	if info, err = file.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil
	}

	hasher := sha256.New()
	tee := io.TeeReader(file, hasher)
	data, err := io.ReadAll(io.LimitReader(tee, filerules.MaxScanBytes))
	note := ""
	if err == nil {
		_, err = io.Copy(io.Discard, tee)
	}
	if err != nil {
		note = "could not be read to its end"
	}
	if int64(len(data)) < info.Size() && err == nil {
		note = fmt.Sprintf("the file rules looked at the first %d bytes", filerules.MaxScanBytes)
	}
	state.files++
	state.bytes += int(info.Size())
	digest := hex.EncodeToString(hasher.Sum(nil))

	before := len(c.result.Events)
	if c.options.FileRules != nil {
		for _, rule := range c.options.FileRules.Rules() {
			hit := rule.MatchSized(name, info.Size(), data)
			if hit == nil {
				continue
			}
			c.add(KindScanned, name, 0, info.ModTime(), TimeFileChange, map[string]string{
				event.Action: ActionFileRule, FileRuleField: rule.Name, "file": "/" + name, "sha256": digest,
				"matched": strings.Join(hit.Strings, ", "), "excerpt": hit.Excerpt, event.User: homeOwner(name),
			})
		}
	}
	if c.options.Indicators.HasHash(digest) {
		c.add(KindScanned, name, 0, info.ModTime(), TimeFileChange, map[string]string{
			event.Action: ActionKnownHash, "file": "/" + name, "sha256": digest, event.User: homeOwner(name),
		})
	}
	if len(c.result.Events) > maxEvents {
		return ErrTooBig
	}
	found := len(c.result.Events) - before

	// A file that was read before (a cron script) keeps its entry. The hash is the same, unless the file
	// changed between the two reads, and that is worth a note.
	if known {
		entry := &c.result.Manifest.Entries[index]
		entry.Events += found
		if entry.SHA256 != digest {
			entry.Note = strings.TrimPrefix(entry.Note+"; it changed while it was read", "; ")
		}

		return nil
	}
	c.result.Manifest.Entries = append(c.result.Manifest.Entries, Entry{
		Path: name, Kind: KindScanned, Size: info.Size(), Mode: info.Mode().String(), Modified: info.ModTime().UTC().Format(time.RFC3339),
		SHA256: digest, Events: found, Note: note,
	})
	if found > 0 {
		c.result.Files = append(c.result.Files, intake.Stats{File: name, Format: KindScanned, Sources: []string{Source}, Events: found})
	}

	return nil
}

func homeOwner(name string) string {
	parts := strings.Split(name, "/")
	if parts[0] == "root" || parts[0] == "home" && len(parts) > 2 {
		return owner(name)
	}

	return ""
}

// AlertRules makes one detection rule for each file rule. The rule fits the events that the scan gives for
// a hit of that file rule, so the hits become alerts with the title and the level of the file rule, and go
// into the same timeline, store and review as all other alerts.
func AlertRules(set filerules.Set) ([]*rules.Rule, error) {
	var made []*rules.Rule
	for _, rule := range set.Rules() {
		description := rule.Description
		if description == "" {
			description = "A file matches the file rule " + rule.Name + "."
		}
		alert, err := rules.Match(rule.Name, rule.ID, rule.Title, description, rule.Level, rule.Tags,
			map[string]string{"product": "linux", "category": "forensics", "service": KindScanned}, FileRuleField, rule.Name)
		if err != nil {
			return nil, err
		}
		made = append(made, alert)
	}

	return made, nil
}

// WithFileRules gives a rule set with the alert rules of the file rules added.
func WithFileRules(set rules.Set, files filerules.Set) (rules.Set, error) {
	made, err := AlertRules(files)
	if err != nil {
		return rules.Set{}, err
	}
	if len(made) == 0 {
		return set, nil
	}
	merged, err := rules.NewSet(append(slices.Clone(set.Rules()), made...))
	if err != nil {
		if errors.Is(err, rules.ErrInvalid) {
			return rules.Set{}, fmt.Errorf("the file rules do not fit with the rules: %w", err)
		}

		return rules.Set{}, err
	}

	return merged, nil
}
