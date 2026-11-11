package gitignore

import (
	"strings"
	"testing"
)

func TestOneFileOfRules(t *testing.T) {
	testCases := []struct {
		name  string
		rules string
		path  string
		want  bool
	}{
		{"a name matches at any depth", ".env", "backend/.env", true},
		{"a name matches at the top", ".env", ".env", true},
		{"a name matches deep", ".env", "a/b/c/.env", true},
		{"a name does not match a longer name", ".env", ".env.local", false},
		{"a name does not match a part of a path", ".env", "env/readme.txt", false},
		{"a slash at the start ties it to the top", "/.env", ".env", true},
		{"a slash at the start does not reach deeper", "/.env", "backend/.env", false},
		{"a slash in the middle ties it to the top", "backend/.env", "backend/.env", true},
		{"a slash in the middle does not reach deeper", "backend/.env", "x/backend/.env", false},
		{"a star", ".env*", ".env.local", true},
		{"a star does not cross a slash", "doc/*.txt", "doc/a/b.txt", false},
		{"a star in a folder", "doc/*.txt", "doc/b.txt", true},
		{"a star at the start", "*.log", "logs/app.log", true},
		{"a question mark", "?.env", "a.env", true},
		{"a question mark is one character", "?.env", "ab.env", false},
		{"a character class", "[ab].env", "b.env", true},
		{"a character class that does not match", "[ab].env", "c.env", false},
		{"a negated character class", "[!ab].env", "c.env", true},
		{"a folder rule ignores what is inside", "build/", "build/out.js", true},
		{"a folder rule ignores deep files", "build/", "x/build/a/b.js", true},
		{"a folder rule does not ignore a file of that name", "build/", "build", false},
		{"a double star at the start", "**/secrets", "a/b/secrets", true},
		{"a double star at the start matches the top", "**/secrets", "secrets", true},
		{"a double star at the end", "secrets/**", "secrets/a/b", true},
		{"a double star at the end does not match the folder", "secrets/**", "secrets", false},
		{"a double star in the middle: no folder between", "a/**/b", "a/b", true},
		{"a double star in the middle: one folder", "a/**/b", "a/x/b", true},
		{"a double star in the middle: two folders", "a/**/b", "a/x/y/b", true},
		{"a double star in the middle: other top", "a/**/b", "c/a/b", false},
		{"a comment", "# .env", ".env", false},
		{"an escaped hash", `\#notes`, "#notes", true},
		{"an escaped exclamation mark", `\!important`, "!important", true},
		{"a blank line", "\n\n", ".env", false},
		{"windows line ends", ".env\r\nnode_modules\r\n", "node_modules/a.js", true},
		{"spaces at the end are removed", ".env   ", ".env", true},
		{"an escaped space at the end is kept", `name\ `, "name ", true},
		{"a later rule takes a file back", ".env*\n!.env.example", ".env.example", false},
		{"a later rule still ignores the others", ".env*\n!.env.example", ".env.local", true},
		{"an earlier negation is overruled", "!.env\n.env", ".env", true},
		{"a file cannot come back from an ignored folder", "build/\n!build/keep.txt", "build/keep.txt", true},
		{"a file can come back from a folder that is not ignored", "*.env\n!keep.env", "keep.env", false},
		{"nothing", "", ".env", false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got := Ignored([]Layer{{Rules: Parse(testCase.rules)}}, testCase.path)

			if got != testCase.want {
				t.Errorf("rules %q, path %q: ignored = %v, want %v", testCase.rules, testCase.path, got, testCase.want)
			}
		})
	}
}

func TestADeeperFileWinsOverAShallowerOneAndOnlyReachesItsOwnFolder(t *testing.T) {
	root := Layer{Rules: Parse(".env\nsecret.txt")}
	backend := Layer{Dir: "backend", Rules: Parse("!.env\n/local.txt")}
	layers := []Layer{root, backend}

	for path, want := range map[string]bool{
		".env":                  true,
		"web/.env":              true,
		"backend/.env":          false,
		"backend/sub/.env":      false,
		"backend/local.txt":     true,
		"backend/sub/local.txt": false,
		"local.txt":             false,
		"backend/secret.txt":    true,
		"other/secret.txt":      true,
	} {
		if got := Ignored(layers, path); got != want {
			t.Errorf("path %q: ignored = %v, want %v", path, got, want)
		}
	}
}

func TestNoLayersAndOddPathsIgnoreNothing(t *testing.T) {
	for _, path := range []string{"", "/", "a", ".env", "a/b/c"} {
		if Ignored(nil, path) {
			t.Errorf("path %q was ignored with no rules", path)
		}
	}
}

func TestBrokenRulesAreSkippedAndNeverBreakTheOthers(t *testing.T) {
	rules := Parse("[\n[a\n\\\n!\n/\n**\n***\n" + strings.Repeat("a", 600) + "\n.env\n")

	if !Ignored([]Layer{{Rules: rules}}, "backend/.env") {
		t.Error("the good rule after the broken ones did not work")
	}
}

func TestTooManyRulesAreCut(t *testing.T) {
	rules := Parse(strings.Repeat("x\n", maxRules+10) + ".env\n")

	if Ignored([]Layer{{Rules: rules}}, ".env") {
		t.Error("a rule after the limit was used")
	}
}

func FuzzParseAndIgnoredNeverPanic(f *testing.F) {
	for _, seed := range []string{"", ".env", "**/a/**/b", "[!a-", "\\", "!\\!", "a/b/\n!a/b/c", "*\n!*/\n", strings.Repeat("**/", 50)} {
		f.Add(seed, "a/b/.env")
	}
	f.Fuzz(func(t *testing.T, rules, path string) {
		Ignored([]Layer{{Rules: Parse(rules)}, {Dir: "a", Rules: Parse(rules)}}, path)
	})
}
