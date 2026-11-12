package tui

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	requestStep = regexp.MustCompile(`^sending request (\d+) to (.+)$`)
	answerStep  = regexp.MustCompile(`^answer received \(step \d+, (\d+) tokens used in total\)$`)
)

type progress struct {
	requests    int
	tokens      int
	provider    string
	maxRequests int
	maxTokens   int
}

// read takes one step text. It returns true when the text only moves the live line and is not worth
// a printed line. Any text that is not known is printed, so a new kind of step is never hidden.
func (current *progress) read(text string) bool {
	if match := requestStep.FindStringSubmatch(text); match != nil {
		current.requests, _ = strconv.Atoi(match[1])
		current.provider = match[2]

		return true
	}
	if match := answerStep.FindStringSubmatch(text); match != nil {
		current.tokens, _ = strconv.Atoi(match[1])

		return true
	}

	return text == "run started" || text == "run finished: finished"
}

func (current progress) percent() int {
	share := 0
	if current.maxRequests > 0 {
		share = current.requests * 100 / current.maxRequests
	}
	if current.maxTokens > 0 {
		share = max(share, current.tokens*100/current.maxTokens)
	}

	return min(max(share, 0), 100)
}

const barWidth = 12

func (current progress) bar() string {
	filled := (current.percent()*barWidth + 99) / 100
	if current.percent() == 0 {
		filled = 0
	}

	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled) + "]"
}

func (current progress) summary() string {
	if current.requests == 0 {
		return "starting"
	}

	text := "request " + strconv.Itoa(current.requests)
	if current.maxRequests > 0 {
		text += " of up to " + strconv.Itoa(current.maxRequests)
	}
	text += " · " + grouped(current.tokens) + " tokens"
	if current.provider != "" {
		text += " · " + current.provider
	}

	return text
}

func grouped(number int) string {
	digits := strconv.Itoa(number)
	var out strings.Builder
	for index, digit := range digits {
		if index > 0 && (len(digits)-index)%3 == 0 {
			out.WriteByte(',')
		}
		out.WriteRune(digit)
	}

	return out.String()
}
