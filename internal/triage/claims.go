package triage

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/authlog"
)

var (
	ErrNoClaims  = errors.New("the AI gave no list of claims")
	ErrBadClaims = errors.New("the list of claims of the AI cannot be read")
)

const (
	BeginMarker = "BEGIN_CLAIMS"
	EndMarker   = "END_CLAIMS"

	maxClaimsBytes = 2 << 20
	maxClaims      = 200
	maxClaimLines  = 5000
	maxClaimUsers  = 500
	maxClaimText   = 200
)

type Claim struct {
	Scenario    string   `json:"scenario"`
	IP          string   `json:"ip"`
	Users       []string `json:"users"`
	Lines       []int    `json:"lines"`
	SuccessLine int      `json:"success_line"`
	Count       int      `json:"count"`
	First       string   `json:"first"`
	Last        string   `json:"last"`
}

// ExtractClaims takes the list of claims out of the text of the AI, and gives back the text without it.
// It uses the last list in the text, because that is the final answer.
func ExtractClaims(text string) (claims []Claim, rest string, err error) {
	begin := strings.LastIndex(text, BeginMarker)
	if begin < 0 {
		return nil, text, ErrNoClaims
	}
	afterBegin := begin + len(BeginMarker)
	end := strings.Index(text[afterBegin:], EndMarker)
	if end < 0 {
		return nil, text, ErrNoClaims
	}

	block := strings.TrimSpace(text[afterBegin : afterBegin+end])
	block = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(block, "```json"), "```"))
	block = strings.TrimSpace(strings.TrimPrefix(block, "```"))
	rest = strings.TrimSpace(text[:begin] + text[afterBegin+end+len(EndMarker):])

	if len(block) > maxClaimsBytes || !utf8.ValidString(block) {
		return nil, rest, ErrBadClaims
	}
	if err := json.Unmarshal([]byte(block), &claims); err != nil || len(claims) > maxClaims {
		return nil, rest, ErrBadClaims
	}
	for _, claim := range claims {
		if len(claim.Lines) > maxClaimLines || len(claim.Users) > maxClaimUsers || len(claim.Scenario) > maxClaimText || len(claim.IP) > maxClaimText ||
			len(claim.First) > maxClaimText || len(claim.Last) > maxClaimText {
			return nil, rest, ErrBadClaims
		}
	}

	return claims, rest, nil
}

// Verdict is the result of the check of one claim. Reasons are fixed texts. They never repeat what the AI wrote.
type Verdict struct {
	Verified bool
	Reasons  []string
	Finding  Finding
}

type Checker struct {
	byLine map[int]authlog.Event
	config Config
}

func NewChecker(parsed authlog.Parsed, config Config) *Checker {
	byLine := make(map[int]authlog.Event, len(parsed.Events))
	for _, event := range parsed.Events {
		byLine[event.Line] = event
	}

	return &Checker{byLine: byLine, config: config}
}

func normalize(stamp string) string {
	return strings.Join(strings.Fields(stamp), " ")
}

// sameStamp says that a claimed time names the time of the line. A classic line must be cited as written. A line
// with an ISO header has its own zone, and a model may write it in the classic way: the same second in the zone
// of the line is accepted then, as written ISO or classic, never a time that is only close.
func sameStamp(claimed string, line authlog.Event) bool {
	text := normalize(claimed)
	if text == line.Stamp {
		return true
	}
	if !strings.Contains(line.Stamp, "T") {
		return false
	}
	second := line.Time.Truncate(time.Second)
	for _, layout := range []string{"Jan _2 15:04:05", "2006-01-02T15:04:05Z07:00", "2006-01-02 15:04:05"} {
		if text == normalize(second.Format(layout)) {
			return true
		}
	}

	return false
}

func (checker *Checker) Check(claim Claim) Verdict {
	var reasons []string
	reject := func(reason string) { reasons = append(reasons, reason) }

	if claim.Scenario != GuessingThenSuccess && claim.Scenario != PasswordSpraying {
		return Verdict{Reasons: []string{"the scenario is not one of the two that are checked"}}
	}
	if len(claim.Lines) == 0 {
		return Verdict{Reasons: []string{"the claim cites no lines"}}
	}

	var cited []authlog.Event
	seen := map[int]bool{}
	for _, number := range claim.Lines {
		event, found := checker.byLine[number]
		switch {
		case seen[number]:
			reject("a line is cited twice")
		case !found:
			reject("a cited line is not a failed or accepted password in the log")
		case event.Kind != authlog.Failed:
			reject("a cited line is not a failed password")
		}
		seen[number] = true
		if found {
			cited = append(cited, event)
		}
	}
	if len(reasons) > 0 {
		return Verdict{Reasons: unique(reasons)}
	}

	first, last := cited[0], cited[len(cited)-1]
	for index, event := range cited {
		if event.IP != claim.IP {
			reject("the source address of a cited line is not the claimed one")
		}
		if index > 0 && (event.Time.Before(cited[index-1].Time) || event.Time.Equal(cited[index-1].Time) && event.Line < cited[index-1].Line) {
			reject("the cited lines are not in time order")
		}
	}
	if claim.Count != len(cited) {
		reject("the count is not the number of cited lines")
	}
	if !sameStamp(claim.First, first) || !sameStamp(claim.Last, last) {
		reject("the first or the last time is not the one of the cited lines")
	}
	if last.Time.Sub(first.Time) > checker.config.Window {
		reject("the cited lines are not within the window")
	}

	users := map[string]bool{}
	for _, event := range cited {
		users[event.User] = true
	}
	var logged []string
	for user := range users {
		logged = append(logged, user)
	}
	slices.Sort(logged)
	claimed := slices.Clone(claim.Users)
	slices.Sort(claimed)
	distinct := slices.Compact(slices.Clone(claimed))
	// The names must be the same set, and each one is named once.
	if !slices.Equal(logged, distinct) || len(distinct) != len(claim.Users) {
		reject("the user names are not the ones of the cited lines")
	}

	var success authlog.Event
	switch claim.Scenario {
	case GuessingThenSuccess:
		if len(logged) != 1 {
			reject("guessing is for one user name, but the cited lines have several")
		}
		if len(cited) < checker.config.FailureThreshold {
			reject("there are fewer failed passwords than the threshold")
		}
		event, found := checker.byLine[claim.SuccessLine]
		switch {
		case !found || event.Kind != authlog.Accepted:
			reject("the success line is not an accepted password in the log")
		case event.IP != first.IP || len(logged) == 1 && event.User != logged[0]:
			reject("the accepted password is from another address or for another user name")
		case event.Time.Before(last.Time) || event.Time.Sub(last.Time) > checker.config.Window:
			reject("the accepted password is not within the window after the last failure")
		default:
			success = event
		}
	case PasswordSpraying:
		if len(logged) < checker.config.SprayThreshold {
			reject("there are fewer different user names than the threshold")
		}
		if claim.SuccessLine != 0 {
			reject("spraying has no success line")
		}
	}

	if len(reasons) > 0 {
		return Verdict{Reasons: unique(reasons)}
	}

	finding := Finding{Scenario: claim.Scenario, IP: first.IP, Users: logged, SuccessLine: success.Line, Count: len(cited),
		First: first.Time, Last: last.Time, FirstStamp: first.Stamp, LastStamp: last.Stamp}
	for _, event := range cited {
		finding.FailureLines = append(finding.FailureLines, event.Line)
	}

	return Verdict{Verified: true, Finding: finding}
}

func unique(reasons []string) []string {
	slices.Sort(reasons)

	return slices.Compact(reasons)
}

func (finding Finding) Describe() string {
	if finding.Scenario == GuessingThenSuccess {
		return fmt.Sprintf("%d failed passwords, then success on line %d", finding.Count, finding.SuccessLine)
	}

	return fmt.Sprintf("%d failed passwords for %d different user names", finding.Count, len(finding.Users))
}
