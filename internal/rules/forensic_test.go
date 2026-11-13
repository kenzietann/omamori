package rules

import "testing"

func TestForensicRulesLoadWithTheBuiltinRulesAndPassTheirOwnTests(t *testing.T) {
	builtin, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	set, err := BuiltinForensics()
	if err != nil {
		t.Fatal(err)
	}
	added := 0
	// These join a log line with an artifact, so they name no kind of artifact. Every other forensic rule does.
	joined := map[string]bool{"forensics_ssh_password_login": true, "forensics_key_after_password_login": true}
	for _, rule := range set.Rules() {
		if joined[rule.Name] {
			if len(rule.tests) < 2 {
				t.Errorf("rule %q needs a test with hits and a test without", rule.Title)
			}
			continue
		}
		if rule.LogSource["category"] != "forensics" {
			continue
		}
		added++
		if len(rule.tests) < 2 && rule.Name != "forensics_extra_root_account" {
			t.Errorf("rule %q needs a test with hits and a test without", rule.Title)
		}
		if rule.LogSource["service"] == "" || rule.LogSource["product"] != "linux" || rule.ID == "" || rule.Description == "" {
			t.Errorf("rule %q must name its kind of artifact, an id and a description", rule.Title)
		}
	}
	if added != 11 || len(set.Rules()) != len(builtin.Rules())+added+len(joined) {
		t.Fatalf("%d forensic rules and %d rules in all, with %d built-in rules", added, len(set.Rules()), len(builtin.Rules()))
	}
	// The detection of logs must stay as it is: none of the forensic rules is in the plain built-in set.
	for _, rule := range builtin.Rules() {
		if rule.LogSource["category"] == "forensics" {
			t.Errorf("rule %q is in the built-in set", rule.Title)
		}
	}
}
