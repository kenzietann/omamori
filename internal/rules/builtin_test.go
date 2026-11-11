package rules

import "testing"

func TestBuiltinRulesLoadAndPassTheirOwnTests(t *testing.T) {
	set, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Rules()) < 15 {
		t.Fatalf("only %d built-in rules were loaded", len(set.Rules()))
	}
	for _, rule := range set.Rules() {
		if len(rule.tests) == 0 {
			t.Errorf("rule %q has no test", rule.Title)
		}
		if rule.ID == "" || rule.Name == "" || rule.Description == "" {
			t.Errorf("rule %q needs an id, a name and a description", rule.Title)
		}
	}
}
