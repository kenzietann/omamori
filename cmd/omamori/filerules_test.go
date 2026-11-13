package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileRulesThroughTheCommandLine(t *testing.T) {
	host := hostFixture(t, false)
	base := t.TempDir()

	none := runAt(t, detectNow, forensicsArgs(host, filepath.Join(base, "none"), "--no-file-rules")...)
	if none.code != exitOK || !strings.Contains(none.stdout, "Read and hashed 22 files: 1254 log events and 77 artifacts. 46 rules. 28 alerts") {
		t.Fatalf("--no-file-rules: %d %s %s", none.code, none.stdout, none.stderr)
	}

	own := filepath.Join(base, "own")
	os.MkdirAll(own, 0o700)
	os.WriteFile(filepath.Join(own, "miner.yml"), []byte(`name: own_miner
title: Our own miner rule
level: critical
strings: {pool: {text: 'stratum+tcp://'}}
condition: pool
tests:
  - {text: 'stratum+tcp://pool.example.test', match: true}
  - {text: 'stratum', match: false}
`), 0o600)
	custom := runAt(t, detectNow, forensicsArgs(host, filepath.Join(base, "custom"), "--file-rules", own)...)
	if custom.code != exitOK || !strings.Contains(custom.stdout, "47 rules. 29 alerts, 4 critical") {
		t.Fatalf("--file-rules: %d %s %s", custom.code, custom.stdout, custom.stderr)
	}
	alerts, _ := os.ReadFile(filepath.Join(base, "custom", "forensics-20261111-030405", "alerts.json"))
	if !strings.Contains(string(alerts), `"rule": "own_miner"`) || strings.Contains(string(alerts), `"rule": "file_coin_miner"`) {
		t.Error("the own file rules did not take the place of the built-in ones")
	}

	both := runAt(t, detectNow, forensicsArgs(host, filepath.Join(base, "both"), "--no-file-rules", "--file-rules", own)...)
	if both.code != exitUsage {
		t.Errorf("both flags: %d", both.code)
	}

	broken := filepath.Join(base, "broken")
	os.MkdirAll(broken, 0o700)
	os.WriteFile(filepath.Join(broken, "bad.yml"), []byte("name: bad\ntitle: Bad\nstrings: {a: {text: x}}\ncondition: a\ntests: [{name: must hit, text: y, match: true}]\n"), 0o600)
	refused := runAt(t, detectNow, forensicsArgs(host, filepath.Join(base, "refused"), "--file-rules", broken)...)
	if refused.code != exitFailed || !strings.Contains(refused.stderr, `test "must hit"`) {
		t.Errorf("a failing file rule: %d %s", refused.code, refused.stderr)
	}
	empty := filepath.Join(base, "empty")
	os.MkdirAll(empty, 0o700)
	if got := runAt(t, detectNow, forensicsArgs(host, filepath.Join(base, "e"), "--file-rules", empty)...); got.code != exitFailed || !strings.Contains(got.stderr, "no file rule") {
		t.Errorf("an empty folder: %d %s", got.code, got.stderr)
	}
	for _, name := range []string{"refused", "e", "both"} {
		if _, err := os.Stat(filepath.Join(base, name)); err == nil {
			t.Errorf("a refused run left the folder %s", name)
		}
	}
}
