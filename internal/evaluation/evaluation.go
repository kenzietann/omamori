package evaluation

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/kenzietann/omamori/internal/mynumber"
	"github.com/kenzietann/omamori/internal/phone"
	"github.com/kenzietann/omamori/internal/secrets"
)

type Example struct {
	Text     string   `json:"text"`
	Expected []string `json:"expected"`
}

// A Detector returns the text of every match, so a corpus file never needs byte positions.
type Detector func(text string) []string

type Score struct {
	TruePositives  int
	FalsePositives int
	FalseNegatives int
}

type Mistake struct {
	Kind  string
	Text  string
	Value string
}

func (score Score) Precision() float64 {
	if score.TruePositives+score.FalsePositives == 0 {
		return 1
	}

	return float64(score.TruePositives) / float64(score.TruePositives+score.FalsePositives)
}

func (score Score) Recall() float64 {
	if score.TruePositives+score.FalseNegatives == 0 {
		return 1
	}

	return float64(score.TruePositives) / float64(score.TruePositives+score.FalseNegatives)
}

func Load(path string) ([]Example, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var examples []Example
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		if len(scanner.Bytes()) == 0 {
			continue
		}

		var example Example
		if err := json.Unmarshal(scanner.Bytes(), &example); err != nil {
			return nil, fmt.Errorf("%s line %d: not valid JSON", path, lineNumber)
		}
		examples = append(examples, example)
	}

	return examples, scanner.Err()
}

// Evaluate counts a match as right only when its text is one of the expected values.
// The same value twice in one text must be found twice.
func Evaluate(detector Detector, examples []Example) (Score, []Mistake) {
	var score Score
	var mistakes []Mistake

	for _, example := range examples {
		remaining := make(map[string]int)
		for _, expected := range example.Expected {
			remaining[expected]++
		}

		for _, found := range detector(example.Text) {
			if remaining[found] > 0 {
				remaining[found]--
				score.TruePositives++
				continue
			}

			score.FalsePositives++
			mistakes = append(mistakes, Mistake{Kind: "false positive", Text: example.Text, Value: found})
		}

		for _, expected := range example.Expected {
			if remaining[expected] > 0 {
				remaining[expected]--
				score.FalseNegatives++
				mistakes = append(mistakes, Mistake{Kind: "miss", Text: example.Text, Value: expected})
			}
		}
	}

	return score, mistakes
}

func MyNumbers(text string) []string {
	var found []string
	for _, match := range mynumber.FindMyNumbers(text) {
		found = append(found, text[match.Start:match.End])
	}

	return found
}

func PhoneNumbers(text string) []string {
	var found []string
	for _, match := range phone.FindPhoneNumbers(text) {
		found = append(found, text[match.Start:match.End])
	}

	return found
}

func Secrets(text string) []string {
	var found []string
	for _, match := range secrets.FindSecrets(text) {
		found = append(found, text[match.Start:match.End])
	}

	return found
}
