package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/analysisrun"
	"github.com/kenzietann/omamori/internal/analyst"
	"github.com/kenzietann/omamori/internal/forensics"
	"github.com/kenzietann/omamori/internal/outbound"
	"github.com/kenzietann/omamori/internal/rules"
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

func TestForensicsThroughTheCommandLine(t *testing.T) {
	host := hostFixture(t, false)
	before := snapshot(t, host)
	output := filepath.Join(t.TempDir(), "out")
	database := filepath.Join(t.TempDir(), "db", "omamori.db")

	got := runAt(t, detectNow, forensicsArgs(host, output, "--db", database)...)
	if got.code != exitOK {
		t.Fatalf("forensics: %d %s", got.code, got.stderr)
	}
	if !strings.Contains(got.stdout, "Read and hashed 22 files: 1254 log events and 77 artifacts. 37 rules. 26 alerts, 3 critical, 14 high, 9 medium.") ||
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

	after := snapshot(t, host)
	if len(after) != len(before) {
		t.Fatal("the run changed the number of files in the evidence")
	}
	for path, content := range before {
		if after[path] != content {
			t.Fatalf("%s was changed", path)
		}
	}

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
	if got.code != exitOK || !strings.Contains(got.stdout, "37 rules. 0 alerts.") {
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
	after := snapshot(t, host)
	if len(after) != len(before) {
		t.Fatalf("refused runs changed the evidence: %d entries before, %d after", len(before), len(after))
	}
	if _, err := os.Stat(output); err == nil {
		t.Fatal("refused runs left a report folder")
	}

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

// forensicSnapshot builds the snapshot that the analyst gets for the host fixture, to script a fake answer.
func forensicSnapshot(t *testing.T, host string) analyst.Snapshot {
	t.Helper()
	set, err := rules.BuiltinForensics()
	if err != nil {
		t.Fatal(err)
	}
	result, err := forensics.Run(filepath.Join(host, "root"), set, "built-in", forensics.Options{
		Year: 2026, Location: time.FixedZone("JST", 9*3600), Processes: filepath.Join(host, "snapshots", "ps.txt"), Sockets: filepath.Join(host, "snapshots", "ss.txt"),
	}, detectNow)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := analyst.BuildSnapshot(result.Outcome)
	if err != nil {
		t.Fatal(err)
	}

	return snapshot
}

func TestForensicsWithTheAnalystThroughTheCommandLine(t *testing.T) {
	host := hostFixture(t, false)
	const awsKey = "AKIAIOSFODNN7EXAMPLE"
	history := filepath.Join(host, "root", "root", ".bash_history")
	data, _ := os.ReadFile(history)
	info, _ := os.Stat(history)
	if err := os.WriteFile(history, []byte(strings.Replace(string(data), "u.sh | sh", "u.sh?k="+awsKey+" | sh", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Chtimes(history, info.ModTime(), info.ModTime())
	before := snapshot(t, host)

	provider := &analystProvider{answer: analystAnswers(t, forensicSnapshot(t, host))}
	factory := func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil }
	common := []string{"--analyze", "--provider", "openai", "--model", "test"}

	// Without --yes: the guarded request is shown, nothing is sent, nothing is written, no database is made.
	database := filepath.Join(t.TempDir(), "db", "omamori.db")
	previewOutput := filepath.Join(t.TempDir(), "preview")
	preview := analyzeCommand(t, factory, forensicsArgs(host, previewOutput, append(common, "--db", database)...)...)
	if preview.code != exitOK || len(provider.sent) != 0 || !strings.Contains(preview.stdout, "Nothing was sent") || !strings.Contains(preview.stdout, "file_modified") {
		t.Fatalf("preview: %d, sent %d, %s", preview.code, len(provider.sent), preview.stderr)
	}
	if strings.Contains(preview.stdout, awsKey) {
		t.Fatal("the preview shows the secret from the history")
	}
	for _, path := range []string{previewOutput, database} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("the preview made %s", path)
		}
	}

	output := filepath.Join(t.TempDir(), "live")
	live := analyzeCommand(t, factory, forensicsArgs(host, output, append(common, "--yes", "--db", database)...)...)
	if live.code != exitOK || len(provider.sent) != 1 {
		t.Fatalf("live: %d %s %s, calls %d", live.code, live.stdout, live.stderr, len(provider.sent))
	}
	if !strings.Contains(live.stdout, "26 verified findings, 0 rejected claims, 0 unreviewed alerts") || !strings.Contains(live.stdout, "Stored run:") {
		t.Errorf("the summary is %q", live.stdout)
	}
	// What left the machine: the bounded snapshot with placeholders. Not the secret, not a private file, no tools.
	sent := provider.sent[0]
	body := sent.System
	for _, message := range sent.Messages {
		body += message.Text
	}
	if strings.Contains(body, awsKey) || !strings.Contains(body, "[SECRET:") || len(sent.Tools) != 0 || !strings.Contains(sent.System, "file_modified") {
		t.Fatal("the request is not the guarded snapshot")
	}
	if strings.Contains(body, host) {
		t.Fatal("the request holds the path of the evidence folder")
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
	report, manifest := read("report.md"), read("manifest.json")
	for _, want := range []string{"# Omamori forensic triage report", "## Attack timeline", "## Evidence manifest", "## AI analyst", "- Verified claims: 26",
		"The checked AI review is shown separately below.", "do not say when or in which order things happened"} {
		if !strings.Contains(report, want) {
			t.Errorf("the report does not have %q", want)
		}
	}
	if strings.Contains(report, awsKey) || strings.Contains(read("alerts.json"), awsKey) || strings.Contains(read("recording.json"), awsKey) {
		t.Error("an output has the secret")
	}
	sum := sha256.Sum256([]byte(manifest))
	digest := hex.EncodeToString(sum[:])
	if read("manifest.sha256") != digest+"  manifest.json\n" || !strings.Contains(live.stdout, "Manifest SHA-256: "+digest) || !strings.Contains(report, digest) {
		t.Error("the manifest, its hash and the report do not agree")
	}
	verified := runAt(t, detectNow, "forensics", "verify", filepath.Join(folder, "manifest.json"), filepath.Join(host, "root"))
	if verified.code != exitOK || !strings.Contains(verified.stdout, "0 are not as the manifest says") {
		t.Fatalf("verify: %d %s", verified.code, verified.stdout)
	}

	var result analysisrun.Result
	if err := json.Unmarshal([]byte(read("analysis.json")), &result); err != nil || !result.Complete || len(result.Analysis.Verified) != 26 {
		t.Fatalf("analysis.json: %v", err)
	}
	weak := 0
	for _, finding := range result.Analysis.Verified {
		if finding.WeakTimes {
			weak++
		}
	}
	if weak != 7 {
		t.Errorf("%d findings are marked as having weak times, want 7", weak)
	}

	runs := decodeStored[[]store.Run](t, storedCommand(t, database, "runs"))
	if len(runs) != 1 || runs[0].AlertCount != 26 || runs[0].EventCount != 1331 {
		t.Fatalf("stored runs: %#v", runs)
	}
	shown := storedCommand(t, database, "run", runs[0].ID)
	if shown.code != exitOK || !strings.Contains(shown.stdout, "do not say when or in which order things happened") || strings.Contains(shown.stdout, awsKey) {
		t.Fatalf("the stored run does not hold the checked analysis: %d %s", shown.code, shown.stderr)
	}

	noProvider := func(_, _, _, _ string) (outbound.Provider, error) {
		t.Fatal("replay created a live provider")
		return nil, nil
	}
	replayOutput := filepath.Join(t.TempDir(), "replay")
	replayed := analyzeCommand(t, noProvider, forensicsArgs(host, replayOutput, "--analyze", "--replay", filepath.Join(folder, "recording.json"))...)
	if replayed.code != exitOK || !strings.Contains(replayed.stdout, "REPLAY") || !strings.Contains(replayed.stdout, "26 verified findings") {
		t.Fatalf("replay: %d %s %s", replayed.code, replayed.stdout, replayed.stderr)
	}
	passwd := filepath.Join(host, "root", "etc", "passwd")
	original, _ := os.ReadFile(passwd)
	passwdInfo, _ := os.Stat(passwd)
	os.WriteFile(passwd, []byte(strings.Replace(string(original), "sysupd", "sysupe", 1)), 0o600)
	stale := analyzeCommand(t, noProvider, forensicsArgs(host, filepath.Join(t.TempDir(), "stale"), "--analyze", "--replay", filepath.Join(folder, "recording.json"))...)
	if stale.code != exitFailed || !strings.Contains(stale.stdout, "0 verified findings") {
		t.Fatalf("replay over changed evidence: %d %s %s", stale.code, stale.stdout, stale.stderr)
	}
	os.WriteFile(passwd, original, 0o600)
	os.Chtimes(passwd, passwdInfo.ModTime(), passwdInfo.ModTime())

	after := snapshot(t, host)
	for path, state := range before {
		if after[path] != state {
			t.Fatalf("%s was changed", path)
		}
	}
}

func TestForensicsAnalystFailsClosedAndKeepsTheTriage(t *testing.T) {
	host := hostFixture(t, false)
	const prose = "the attacker is certainly gone and the system is safe"
	provider := &analystProvider{answer: prose}
	output := filepath.Join(t.TempDir(), "out")
	got := analyzeCommand(t, func(_, _, _, _ string) (outbound.Provider, error) { return provider, nil },
		forensicsArgs(host, output, "--analyze", "--yes", "--provider", "openai", "--model", "test")...)
	if got.code != exitFailed || !strings.Contains(got.stderr, "analysis is incomplete") {
		t.Fatalf("invalid answer: %d %s %s", got.code, got.stdout, got.stderr)
	}
	files := analysisFiles(t, output)
	for _, name := range []string{"report.md", "report.html", "analysis.json", "alerts.json", "manifest.json", "manifest.sha256"} {
		data, err := os.ReadFile(files[name])
		if err != nil || strings.Contains(string(data), prose) {
			t.Fatalf("%s is missing or holds the text of the model: %v", name, err)
		}
	}
	report, _ := os.ReadFile(files["report.md"])
	if !strings.Contains(string(report), "## Attack timeline") || !strings.Contains(string(report), "forensics_extra_root_account") && !strings.Contains(string(report), "A second account has the user number of root") {
		t.Fatal("the triage is not in the report after the invalid answer")
	}
}

func TestForensicsAnalystFlags(t *testing.T) {
	host := hostFixture(t, true)
	root := filepath.Join(host, "root")
	output := filepath.Join(t.TempDir(), "out")
	for name, args := range map[string][]string{
		"yes without analyze":     {"forensics", "--yes", root, "--output", output},
		"dry run without analyze": {"forensics", "--dry-run", root, "--output", output},
		"replay without analyze":  {"forensics", "--replay", "recording.json", root, "--output", output},
		"yes with dry run":        {"forensics", "--analyze", "--yes", "--dry-run", root, "--output", output},
		"timeout of zero":         {"forensics", "--analyze", "--timeout", "0s", root, "--output", output},
	} {
		if got := runAt(t, detectNow, args...); got.code != exitUsage || !strings.Contains(got.stderr, "usage: omamori forensics") {
			t.Errorf("%s: code %d, stderr %q", name, got.code, got.stderr)
		}
	}
	if _, err := os.Stat(output); err == nil {
		t.Fatal("a refused run left a report folder")
	}

	// A system without alerts needs no provider: nothing is sent, and the run is complete.
	quiet := analyzeCommand(t, func(_, _, _, _ string) (outbound.Provider, error) {
		t.Fatal("a provider was made for a run without alerts")
		return nil, nil
	}, forensicsArgs(host, output, "--analyze", "--yes")...)
	if quiet.code != exitOK || !strings.Contains(quiet.stdout, "Nothing will be sent to an AI provider") {
		t.Fatalf("no alerts: %d %s %s", quiet.code, quiet.stdout, quiet.stderr)
	}
}
