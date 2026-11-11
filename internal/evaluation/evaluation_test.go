package evaluation

import (
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestScore(t *testing.T) {
	testCases := []struct {
		name          string
		score         Score
		wantPrecision float64
		wantRecall    float64
	}{
		{"all right", Score{TruePositives: 8}, 1, 1},
		{"one false alarm", Score{TruePositives: 3, FalsePositives: 1}, 0.75, 1},
		{"one miss", Score{TruePositives: 3, FalseNegatives: 1}, 1, 0.75},
		{"both", Score{TruePositives: 2, FalsePositives: 2, FalseNegatives: 6}, 0.5, 0.25},
		{"nothing found, nothing expected", Score{}, 1, 1},
		{"nothing found, something expected", Score{FalseNegatives: 2}, 1, 0},
		{"only false alarms", Score{FalsePositives: 2}, 0, 1},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotPrecision := testCase.score.Precision()
			gotRecall := testCase.score.Recall()

			if math.Abs(gotPrecision-testCase.wantPrecision) > 1e-9 || math.Abs(gotRecall-testCase.wantRecall) > 1e-9 {
				t.Errorf("precision, recall = %v, %v, want %v, %v", gotPrecision, gotRecall, testCase.wantPrecision, testCase.wantRecall)
			}
		})
	}
}

func TestEvaluate(t *testing.T) {
	findWords := func(text string) []string { return strings.Fields(text) }

	testCases := []struct {
		name         string
		example      Example
		wantScore    Score
		wantMistakes []string
	}{
		{"exact", Example{"aa bb", []string{"aa", "bb"}}, Score{TruePositives: 2}, nil},
		{"false positive", Example{"aa bb", []string{"aa"}}, Score{TruePositives: 1, FalsePositives: 1}, []string{"false positive bb"}},
		{"miss", Example{"aa", []string{"aa", "cc"}}, Score{TruePositives: 1, FalseNegatives: 1}, []string{"miss cc"}},
		{"nothing expected, nothing found", Example{"", nil}, Score{}, nil},
		{"the same value twice must be found twice", Example{"aa", []string{"aa", "aa"}}, Score{TruePositives: 1, FalseNegatives: 1}, []string{"miss aa"}},
		{"a found value twice is one extra", Example{"aa aa", []string{"aa"}}, Score{TruePositives: 1, FalsePositives: 1}, []string{"false positive aa"}},
		{"a part of the value is not enough", Example{"aaa", []string{"aaaa"}}, Score{FalsePositives: 1, FalseNegatives: 1}, []string{"false positive aaa", "miss aaaa"}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotScore, gotMistakes := Evaluate(findWords, []Example{testCase.example})

			if gotScore != testCase.wantScore {
				t.Errorf("score = %+v, want %+v", gotScore, testCase.wantScore)
			}
			var gotDescriptions []string
			for _, mistake := range gotMistakes {
				gotDescriptions = append(gotDescriptions, mistake.Kind+" "+mistake.Value)
			}
			if !slices.Equal(gotDescriptions, testCase.wantMistakes) {
				t.Errorf("mistakes = %v, want %v", gotDescriptions, testCase.wantMistakes)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	directory := t.TempDir()
	goodPath := filepath.Join(directory, "good.jsonl")
	badPath := filepath.Join(directory, "bad.jsonl")
	os.WriteFile(goodPath, []byte("{\"text\":\"a\",\"expected\":[\"a\"]}\n\n{\"text\":\"b\",\"expected\":[]}\n"), 0o644)
	os.WriteFile(badPath, []byte("{\"text\":\"a\"}\nnot json\n"), 0o644)

	gotExamples, err := Load(goodPath)
	if err != nil || len(gotExamples) != 2 || gotExamples[0].Expected[0] != "a" {
		t.Errorf("Load(good) = %v, %v, want 2 examples and no error", gotExamples, err)
	}

	if _, err := Load(badPath); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("Load(bad) error = %v, want an error that names line 2", err)
	}
	if _, err := Load(filepath.Join(directory, "missing.jsonl")); err == nil {
		t.Error("Load(missing) returned no error")
	}
}

// The targets were written before the first measurement. A miss costs more than a false alarm,
// so recall is the stricter number. My Number has the lowest precision target, because the check
// digit lets about 1 in 10 random 12-digit numbers pass.
var targets = map[string]struct {
	detector     Detector
	minPrecision float64
	minRecall    float64
}{
	"secrets":  {Secrets, 0.85, 0.95},
	"phone":    {PhoneNumbers, 0.80, 0.95},
	"mynumber": {MyNumbers, 0.70, 0.95},
}

func TestCorpusTargets(t *testing.T) {
	for _, name := range []string{"secrets", "phone", "mynumber"} {
		for _, set := range []string{"dev", "heldout"} {
			t.Run(name+"-"+set, func(t *testing.T) {
				examples, err := Load(filepath.Join("..", "..", "testdata", "corpus", name+"-"+set+".jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				if len(examples) < 10 {
					t.Fatalf("the corpus has only %d examples", len(examples))
				}

				gotScore, gotMistakes := Evaluate(targets[name].detector, examples)

				t.Logf("%d examples: precision %.2f, recall %.2f (%d right, %d false alarms, %d misses)",
					len(examples), gotScore.Precision(), gotScore.Recall(), gotScore.TruePositives, gotScore.FalsePositives, gotScore.FalseNegatives)
				for _, mistake := range gotMistakes {
					t.Logf("  %s: %q in %q", mistake.Kind, mistake.Value, mistake.Text)
				}

				// The dev set holds hostile look-alikes on purpose, to find false alarms. Only the
				// held-out set, which was not used to build the detectors, must meet the precision target.
				if set == "heldout" && gotScore.Precision() < targets[name].minPrecision {
					t.Errorf("precision %.2f is below the target %.2f", gotScore.Precision(), targets[name].minPrecision)
				}
				if gotScore.Recall() < targets[name].minRecall {
					t.Errorf("recall %.2f is below the target %.2f", gotScore.Recall(), targets[name].minRecall)
				}
			})
		}
	}
}
