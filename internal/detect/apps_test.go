package detect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/intake"
	"github.com/kenzietann/omamori/internal/rules"
)

// The logs in testdata/fixtures/apps were written by real applications of sixteen setups of the most used backend
// frameworks during the same attack (testdata/applab): fifteen in Docker, and Fastify's standard output as a
// process manager keeps it. Each file must be read whole, and exactly the
// rules in expected.json must fire: a rule that stops firing is a missed attack, and a new one a false alarm.
func TestRealLogsOfTheFrameworks(t *testing.T) {
	folder := filepath.Join("..", "..", "testdata", "fixtures", "apps")
	data, err := os.ReadFile(filepath.Join(folder, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]map[string][]string
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) != 16 {
		t.Fatalf("%d setups in expected.json, want 16", len(expected))
	}
	for app, files := range expected {
		for file, want := range files {
			t.Run(app+"/"+file, func(t *testing.T) {
				outcome, err := Run([]string{filepath.Join(folder, app, file)}, set, "built-in", intake.Options{Year: 2026, Location: time.UTC}, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if len(outcome.Intake.Files) != 1 || outcome.Intake.Files[0].Malformed != 0 || outcome.Intake.Files[0].Events == 0 {
					t.Fatalf("read: %+v", outcome.Intake.Files)
				}
				var got []string
				for _, alert := range outcome.Result.Alerts {
					if !slices.Contains(got, alert.Rule.Name) {
						got = append(got, alert.Rule.Name)
					}
				}
				sort.Strings(got)
				sort.Strings(want)
				if !slices.Equal(got, want) {
					t.Errorf("rules\n got %v\nwant %v", got, want)
				}
			})
		}
	}
}
