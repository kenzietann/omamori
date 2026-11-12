package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/store"
)

// hostFixture writes the synthetic system through the real command.
func hostFixture(t *testing.T, benign bool) string {
	t.Helper()
	folder := filepath.Join(t.TempDir(), "host")
	args := []string{"scenario", "--host", "--seed", "3", "--date", "2026-11-10", "--timezone", "Asia/Tokyo", folder}
	if benign {
		args = append(args, "--benign")
	}
	if made := runAt(t, detectNow, args...); made.code != exitOK {
		t.Fatalf("scenario --host: %d %s", made.code, made.stderr)
	}

	return folder
}

func forensicsArgs(host, output string, more ...string) []string {
	return append([]string{"forensics", "--year", "2026", "--timezone", "Asia/Tokyo", "--processes", filepath.Join(host, "snapshots", "ps.txt"),
		"--sockets", filepath.Join(host, "snapshots", "ss.txt"), "--output", output, filepath.Join(host, "root")}, more...)
}

// The path of the slice through the real command line: a system in, a report with a timeline, a manifest that
// can be checked again, and a stored run whose events can be searched.
func TestForensicsThroughTheCommandLine(t *testing.T) {
	host := hostFixture(t, false)
	before := snapshot(t, host)
	output := filepath.Join(t.TempDir(), "out")
	database := filepath.Join(t.TempDir(), "db", "omamori.db")

	got := runAt(t, detectNow, forensicsArgs(host, output, "--db", database)...)
	if got.code != exitOK {
		t.Fatalf("forensics: %d %s", got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, "Read and hashed 22 files: 1254 log events and 77 artifacts. 27 rules. 26 alerts, 3 critical, 14 high, 9 medium.") ||
		!strings.Contains(got.stdout, "Stored run:") {
		t.Errorf("the summary is %q", got.stdout)
	}

	folder := filepath.Join(output, "forensics-20261111-030405")
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(folder, name))
		if err != nil {
			t.Fatal(err)
		}

		return string(data)
	}
	report, page, manifest, digest, alerts := read("report.md"), read("report.html"), read("manifest.json"), read("manifest.sha256"), read("alerts.json")
	sum := sha256.Sum256([]byte(manifest))
	if digest != hex.EncodeToString(sum[:])+"  manifest.json\n" || !strings.Contains(got.stdout, "Manifest SHA-256: "+hex.EncodeToString(sum[:])) {
		t.Error("manifest.sha256 is not the hash of manifest.json")
	}
	if !strings.Contains(report, "## Attack timeline") || !strings.Contains(page, "<td>written in the history</td>") || !strings.Contains(page, "default-src 'none'") {
		t.Error("the reports have no timeline")
	}
	var expected struct {
		Alerts []struct{ Rule string } `json:"expected_alerts"`
	}
	if err := json.Unmarshal([]byte(before[filepath.Join(host, "expected.json")]), &expected); err != nil || len(expected.Alerts) != 22 {
		t.Fatalf("expected.json: %v, %d alerts", err, len(expected.Alerts))
	}
	for _, wanted := range expected.Alerts {
		if !strings.Contains(alerts, `"rule": "`+wanted.Rule+`"`) {
			t.Errorf("alerts.json does not have %s", wanted.Rule)
		}
	}

	// The evidence is as it was: content, modes and times.
	after := snapshot(t, host)
	if len(after) != len(before) {
		t.Fatal("the run changed the number of files in the evidence")
	}
	for path, content := range before {
		if after[path] != content {
			t.Fatalf("%s was changed", path)
		}
	}

	// The stored run holds the artifacts next to the log events, and they can be searched by kind.
	runs := decodeStored[[]store.Run](t, storedCommand(t, database, "runs"))
	if len(runs) != 1 || runs[0].EventCount != 1331 || runs[0].AlertCount != 26 {
		t.Fatalf("stored run: %#v", runs)
	}
	keys := decodeStored[[]store.Event](t, storedCommand(t, database, "search", "--run", runs[0].ID, "--field", "service", "--value", "authorized_keys"))
	if len(keys) != 6 || !strings.HasPrefix(keys[0].Fields["fingerprint"], "SHA256:") {
		t.Fatalf("%d stored keys", len(keys))
	}
	critical := decodeStored[[]store.Alert](t, storedCommand(t, database, "search", "--kind", "alerts", "--level", "critical"))
	if len(critical) != 3 {
		t.Fatalf("%d stored critical alerts", len(critical))
	}

	// The manifest still fits the evidence. After one byte is changed, it does not, and the command fails.
	verified := runAt(t, detectNow, "forensics", "verify", filepath.Join(folder, "manifest.json"), filepath.Join(host, "root"))
	if verified.code != exitOK || !strings.Contains(verified.stdout, "Checked 20 files. 0 are not as the manifest says.") {
		t.Fatalf("verify: %d %q %q", verified.code, verified.stdout, verified.stderr)
	}
	passwd := filepath.Join(host, "root", "etc", "passwd")
	data, _ := os.ReadFile(passwd)
	if err := os.WriteFile(passwd, []byte(strings.Replace(string(data), "sysupd", "sysupe", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	verified = runAt(t, detectNow, "forensics", "verify", filepath.Join(folder, "manifest.json"), filepath.Join(host, "root"))
	if verified.code != exitFailed || !strings.Contains(verified.stdout, "etc/passwd: the content has changed") || !strings.Contains(verified.stdout, "1 are not as the manifest says") {
		t.Fatalf("verify after a change: %d %q", verified.code, verified.stdout)
	}
}

func TestForensicsOnTheSystemWithoutAnAttack(t *testing.T) {
	host := hostFixture(t, true)
	got := runAt(t, detectNow, forensicsArgs(host, filepath.Join(t.TempDir(), "out"))...)
	if got.code != exitOK || !strings.Contains(got.stdout, "27 rules. 0 alerts.") {
		t.Fatalf("code %d, stdout %q, stderr %q", got.code, got.stdout, got.stderr)
	}
}

func TestForensicsRefusals(t *testing.T) {
	host := hostFixture(t, false)
	root := filepath.Join(host, "root")
	base := t.TempDir()
	empty := filepath.Join(base, "empty")
	os.Mkdir(empty, 0o700)
	output := filepath.Join(base, "out")
	file := filepath.Join(base, "file.txt")
	os.WriteFile(file, []byte("{"), 0o600)

	cases := []struct {
		name string
		args []string
		code int
		want string
	}{
		{"no folder", []string{"forensics"}, exitUsage, "usage: omamori forensics"},
		{"two folders", []string{"forensics", root, root}, exitUsage, "usage: omamori forensics"},
		{"unknown flag", []string{"forensics", "--write", root}, exitUsage, "usage: omamori forensics"},
		{"missing folder", []string{"forensics", filepath.Join(base, "none"), "--output", output}, exitFailed, "evidence folder cannot be read"},
		{"a file in place of a folder", []string{"forensics", file, "--output", output}, exitFailed, "evidence folder cannot be read"},
		{"folder that is no system", []string{"forensics", empty, "--output", output}, exitFailed, "no artifact was found"},
		{"report folder inside the evidence", []string{"forensics", root, "--output", filepath.Join(root, "tmp")}, exitFailed, "must not be inside the evidence"},
		{"report folder around the evidence", []string{"forensics", filepath.Join(root, "etc"), "--output", filepath.Join(root, "etc", "..", "etc", "x")}, exitFailed, "must not be inside the evidence"},
		{"missing snapshot", []string{"forensics", root, "--processes", filepath.Join(base, "ps.txt"), "--output", output}, exitFailed, "snapshot file"},
		{"unknown time zone", []string{"forensics", root, "--timezone", "Mars/Olympus", "--output", output}, exitFailed, "time zone"},
		{"verify without arguments", []string{"forensics", "verify"}, exitUsage, "omamori forensics verify"},
		{"verify with a missing manifest", []string{"forensics", "verify", filepath.Join(base, "m.json"), root}, exitFailed, "manifest cannot be read"},
		{"verify with a manifest that is no manifest", []string{"forensics", "verify", file, root}, exitFailed, "manifest cannot be read"},
	}
	before := snapshot(t, host)
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := runAt(t, detectNow, testCase.args...)
			if got.code != testCase.code || !strings.Contains(got.stderr, testCase.want) {
				t.Fatalf("code %d, stderr %q", got.code, got.stderr)
			}
		})
	}
	// Refused runs wrote nothing: not into the evidence and not into the report folder.
	after := snapshot(t, host)
	if len(after) != len(before) {
		t.Fatalf("refused runs changed the evidence: %d entries before, %d after", len(before), len(after))
	}
	if _, err := os.Stat(output); err == nil {
		t.Fatal("refused runs left a report folder")
	}

	// The same second again: the report of the first run is not written over.
	first := runAt(t, detectNow, forensicsArgs(host, output)...)
	second := runAt(t, detectNow, forensicsArgs(host, output)...)
	if first.code != exitOK || second.code != exitFailed || !strings.Contains(second.stderr, "exists already") {
		t.Fatalf("first %d, second %d %q", first.code, second.code, second.stderr)
	}
}

func TestHostScenarioRefusesAnExistingFolder(t *testing.T) {
	existing := t.TempDir()
	got := runAt(t, detectNow, "scenario", "--host", existing)
	if got.code != exitFailed || !strings.Contains(got.stderr, "exists already") {
		t.Fatalf("code %d, stderr %q", got.code, got.stderr)
	}
	if entries, _ := os.ReadDir(existing); len(entries) != 0 {
		t.Fatal("a refused scenario wrote something")
	}
}
