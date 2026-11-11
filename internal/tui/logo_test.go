package tui

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
	"github.com/muesli/termenv"
)

var styleCodes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestMain(m *testing.M) {
	lipgloss.SetColorProfile(termenv.Ascii)
	lipgloss.SetHasDarkBackground(true)
	spinnerInterval = 0

	os.Exit(m.Run())
}

func withProfile(t testing.TB, profile termenv.Profile) {
	t.Helper()

	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(profile)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })
}

func sized(model Model, width, height int) Model {
	updated, _ := model.Update(tea.WindowSizeMsg{Width: width, Height: height})

	return updated.(Model)
}

func TestEveryLineOfTheLiveAreaFitsTheWindow(t *testing.T) {
	for _, profile := range []termenv.Profile{termenv.Ascii, termenv.TrueColor} {
		withProfile(t, profile)

		for _, size := range [][2]int{{80, 30}, {40, 30}, {20, 12}, {200, 50}, {100, 60}, {60, 50}} {
			home := sized(newModel("/very/long/folder/name/that/goes/on/and/on", finishedRunner("r", true)), size[0], size[1])
			running, _ := beginRun(t, home)

			for name, model := range map[string]Model{"home": home, "run": sized(running, size[0], size[1])} {
				for _, line := range strings.Split(styleCodes.ReplaceAllString(model.View(), ""), "\n") {
					if runewidth.StringWidth(line) > size[0] {
						t.Errorf("profile %v, %dx%d, %s: the line %q is wider than the window", profile, size[0], size[1], name, line)
					}
				}
			}
		}
	}
}

func TestJapaneseTextIsCutByDisplayWidth(t *testing.T) {
	target := strings.Repeat("日本語のファイル名", 10)
	model := sized(newModel(target, nil), 30, 12)

	for _, line := range strings.Split(model.View(), "\n") {
		if runewidth.StringWidth(line) > 30 {
			t.Errorf("the line %q is %d columns wide", line, runewidth.StringWidth(line))
		}
	}
}

func TestColorsDependOnTheContent(t *testing.T) {
	withProfile(t, termenv.TrueColor)

	report := strings.Join([]string{
		"# Omamori report",
		"Status: complete",
		"| [SECRET:aws-access-key:001] | high | aws-access-key | a.py | 3 |",
		"| [PHONE:001] | medium | phone | b.csv | 2 |",
		"plain line",
	}, "\n")
	model, command := startedRun(t, finishedRunner(report, true))
	view := strings.Join(settle(model, command).transcript, "\n")

	lineWith := func(text string) string {
		for _, line := range strings.Split(view, "\n") {
			if strings.Contains(line, text) {
				return line
			}
		}
		t.Fatalf("no line has %q", text)
		return ""
	}

	checks := []struct {
		text   string
		want   string
		reject string
	}{
		{"| high |", "38;2;255;123;123", "38;2;245;176;65"},
		{"| medium |", "38;2;245;176;65", "38;2;255;123;123"},
		{"Status: complete", "38;2;73;222;128", "38;2;255;123;123"},
		{"Results: Task A, complete", "38;2;73;222;128", "38;2;245;176;65"},
		{"plain line", "38;2;231;237;246", "38;2;255;123;123"},
	}
	for _, check := range checks {
		line := lineWith(check.text)
		if !strings.Contains(line, check.want) || strings.Contains(line, check.reject) {
			t.Errorf("the line with %q has the wrong color: %q", check.text, line)
		}
	}

	incomplete, command := startedRun(t, finishedRunner("partial", false))
	for _, line := range strings.Split(strings.Join(settle(incomplete, command).transcript, "\n"), "\n") {
		if strings.Contains(line, "Results: Task A, incomplete") && !strings.Contains(line, "38;2;245;176;65") {
			t.Errorf("an incomplete result is not amber: %q", line)
		}
	}
}

func TestOnlyOurStylingMakesEscapeCodes(t *testing.T) {
	withProfile(t, termenv.TrueColor)

	hostile := "a\x1b[999mred\x1b]0;title\x07 b‮evil c\x00d"
	runner := func(ctx context.Context, step func(string)) (Result, error) {
		step(hostile)
		return Result{Report: hostile, Complete: true}, nil
	}
	home := newModel(hostile, runner)
	running, command := beginRun(t, home)
	results := settle(running, command)
	failed, failCommand := startedRun(t, func(ctx context.Context, step func(string)) (Result, error) {
		return Result{}, errors.New(hostile)
	})
	failed = settle(failed, failCommand)

	for name, model := range map[string]Model{"home": home, "run": running, "results": results, "error": failed} {
		view := model.View() + strings.Join(model.transcript, "\n")

		if strings.Contains(view, "\x1b[999m") || strings.Contains(view, "\x1b]") {
			t.Errorf("%s: an escape code from the input got through", name)
		}
		for _, character := range styleCodes.ReplaceAllString(view, "") {
			if character != '\n' && (unicode.IsControl(character) || unicode.Is(unicode.Cf, character)) {
				t.Errorf("%s: the view holds the character %U", name, character)
			}
		}
	}
}
func TestWordmarkIsWellFormed(t *testing.T) {
	if len(wordmarkRows) != 6 || wordmarkWidth() != 59 {
		t.Errorf("the wordmark is %d rows and %d wide, want 6 and 59", len(wordmarkRows), wordmarkWidth())
	}
	for index, row := range wordmarkRows {
		if utf8.RuneCountInString(row) != wordmarkWidth() {
			t.Errorf("row %d is %d wide, every row must be %d wide (a lost space breaks the letters)", index, utf8.RuneCountInString(row), wordmarkWidth())
		}
		if strings.Trim(row, " █╗╔╝╚═║") != "" {
			t.Errorf("row %d has an unexpected character: %q", index, row)
		}
	}
	if wordmarkWidth() > 80 {
		t.Error("the wordmark does not fit 80 columns")
	}
}

func TestWordmarkMatchesTheArt(t *testing.T) {
	want := []string{
		" ██████╗ ███╗   ███╗ █████╗ ███╗   ███╗ ██████╗ ██████╗ ██╗",
		"██╔═══██╗████╗ ████║██╔══██╗████╗ ████║██╔═══██╗██╔══██╗██║",
		"██║   ██║██╔████╔██║███████║██╔████╔██║██║   ██║██████╔╝██║",
		"██║   ██║██║╚██╔╝██║██╔══██║██║╚██╔╝██║██║   ██║██╔══██╗██║",
		"╚██████╔╝██║ ╚═╝ ██║██║  ██║██║ ╚═╝ ██║╚██████╔╝██║  ██║██║",
		" ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝",
	}
	if len(wordmarkRows) != len(want) {
		t.Fatalf("the wordmark has %d rows, want %d", len(wordmarkRows), len(want))
	}
	for index := range want {
		if wordmarkRows[index] != want[index] {
			t.Errorf("row %d:\n got  %q\n want %q", index, wordmarkRows[index], want[index])
		}
	}
}

func TestWithoutColorTheWordmarkIsPlain(t *testing.T) {
	view := newModel("/work/project", nil).View()

	if strings.Contains(view, "\x1b") {
		t.Error("the plain view holds an escape code")
	}
	for index, row := range wordmarkRows {
		if !strings.Contains(view, row) {
			t.Errorf("the view has no wordmark row %d: %q", index, row)
		}
	}
	if !strings.Contains(view, "a blue team helper with a guard") {
		t.Error("the tagline is missing")
	}
}

func TestSmallWindowsGetAOneLineHeader(t *testing.T) {
	testCases := []struct {
		name   string
		width  int
		height int
	}{
		{"narrow", wordmarkWidth() - 1, 40},
		{"short", 100, minWordmarkHeight - 1},
		{"both", 40, 10},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			view := sized(newModel("/work/project", nil), testCase.width, testCase.height).View()

			if strings.ContainsAny(view, "█╗╔╝╚║") || !strings.Contains(view, "OMAMORI") {
				t.Errorf("the header is not the small one:\n%s", view)
			}
		})
	}

	exact := sized(newModel("/work/project", nil), wordmarkWidth(), minWordmarkHeight)
	if !strings.Contains(exact.View(), wordmarkRows[1]) {
		t.Error("a window that is exactly big enough did not get the wordmark")
	}
	withNotice, _ := pressAll(t, exact, "down", "enter")
	if lines := strings.Count(withNotice.View(), "\n") + 1; lines > minWordmarkHeight || !strings.Contains(withNotice.View(), "not built yet") {
		t.Errorf("with a notice the menu has %d lines in a window of %d", lines, minWordmarkHeight)
	}
}

var colorCode = regexp.MustCompile(`38;2;(\d+);(\d+);(\d+)m`)

func colorsIn(t testing.TB, line string) []rgb {
	t.Helper()

	var colors []rgb
	for _, match := range colorCode.FindAllStringSubmatch(line, -1) {
		red, _ := strconv.Atoi(match[1])
		green, _ := strconv.Atoi(match[2])
		blue, _ := strconv.Atoi(match[3])
		colors = append(colors, rgb{red, green, blue})
	}

	return colors
}

// The color library turns a hex color into numbers and may be one off from ours.
func nearColor(first, second rgb) bool {
	close := func(a, b int) bool { return a-b <= 1 && b-a <= 1 }

	return close(first.red, second.red) && close(first.green, second.green) && close(first.blue, second.blue)
}

func TestGradientColors(t *testing.T) {
	testCases := []struct {
		name     string
		position float64
		want     rgb
	}{
		{"left end", 0, rgb{56, 189, 248}},
		{"middle is the brand blue", 0.5, rgb{58, 127, 246}},
		{"right end", 1, rgb{155, 107, 255}},
		{"below the range is the left end", -3, rgb{56, 189, 248}},
		{"above the range is the right end", 7, rgb{155, 107, 255}},
		{"a quarter of the way", 0.25, rgb{57, 158, 247}},
	}
	for _, testCase := range testCases {
		if got := gradientColor(testCase.position); got != testCase.want {
			t.Errorf("%s: gradientColor(%v) = %+v, want %+v", testCase.name, testCase.position, got, testCase.want)
		}
	}

	previous := gradientColor(0)
	for column := 1; column < 59; column++ {
		current := gradientColor(float64(column) / 58)
		for name, change := range map[string]int{"red": current.red - previous.red, "green": current.green - previous.green, "blue": current.blue - previous.blue} {
			if change > 8 || change < -8 {
				t.Errorf("column %d: the %s channel jumps by %d, the gradient is not smooth", column, name, change)
			}
		}
		previous = current
	}

	if got := darken(rgb{100, 200, 250}, 0.5); got != (rgb{50, 100, 125}) {
		t.Errorf("darken = %+v, want {50 100 125}", got)
	}
	if got := darken(rgb{250, 250, 250}, 9); got != (rgb{255, 255, 255}) {
		t.Errorf("darken does not stop at 255: %+v", got)
	}
	if got := gradientColor(0).hex(); got != "#38bdf8" {
		t.Errorf("hex = %q, want #38bdf8", got)
	}
}

func TestWithColorTheWordmarkIsAGradientWithShadows(t *testing.T) {
	withProfile(t, termenv.TrueColor)

	lines := strings.Split(newModel("/work/project", nil).View(), "\n")
	for index, wantRow := range wordmarkRows {
		line := lines[index]

		if got := styleCodes.ReplaceAllString(line, ""); got != wantRow {
			t.Errorf("row %d: colors changed the text: %q, want %q", index, got, wantRow)
		}
		if distinct := len(map[rgb]bool(distinctColors(colorsIn(t, line)))); distinct < 10 {
			t.Errorf("row %d has only %d different colors, want a gradient", index, distinct)
		}
	}

	left := colorsIn(t, lines[1])[0]
	if !nearColor(left, gradientColor(0)) {
		t.Errorf("the first block is %+v, want the left end %+v", left, gradientColor(0))
	}
	rightColors := colorsIn(t, lines[1])
	right := rightColors[len(rightColors)-1]
	if !nearColor(right, darken(gradientColor(1), shadowStrength)) {
		t.Errorf("the last shadow is %+v, want the dark right end %+v", right, darken(gradientColor(1), shadowStrength))
	}

	// Row 2 has a block and a shadow side by side at columns 1 and 2: "██║". The shadow is darker.
	row2 := colorsIn(t, lines[2])
	block, shadow := row2[1], row2[2]
	if shadow.red >= block.red && shadow.green >= block.green && shadow.blue >= block.blue {
		t.Errorf("the shadow %+v is not darker than the block %+v", shadow, block)
	}

	taglineLines := 0
	for _, line := range lines {
		if strings.Contains(styleCodes.ReplaceAllString(line, ""), "a blue team helper") {
			taglineLines++
			if len(distinctColors(colorsIn(t, line))) != 1 {
				t.Errorf("the tagline is not one gray color: %q", line)
			}
		}
	}
	if taglineLines != 1 {
		t.Errorf("found the tagline on %d lines, want 1", taglineLines)
	}
}

var coloredCharacter = regexp.MustCompile(`\x1b\[38;2;(\d+);(\d+);(\d+)m(.)\x1b\[0m`)

func TestEveryCharacterHasTheColorOfItsColumn(t *testing.T) {
	withProfile(t, termenv.TrueColor)

	lines := strings.Split(newModel("/work/project", nil).View(), "\n")
	checked := 0
	for rowIndex := range wordmarkRows {
		line := lines[rowIndex]

		for _, match := range coloredCharacter.FindAllStringSubmatchIndex(line, -1) {
			column := utf8.RuneCountInString(styleCodes.ReplaceAllString(line[:match[0]], ""))
			character := line[match[8]:match[9]]
			got := colorsIn(t, line[match[0]:match[1]])[0]

			want := gradientColor(float64(column) / float64(wordmarkWidth()-1))
			if character != "█" {
				want = darken(want, shadowStrength)
			}
			if !nearColor(got, want) {
				t.Errorf("row %d column %d (%s): color %+v, want %+v", rowIndex, column, character, got, want)
			}
			if brightest := max(got.red, got.green, got.blue); brightest < 100 {
				t.Errorf("row %d column %d: color %+v is too dark to see on a dark terminal", rowIndex, column, got)
			}
			checked++
		}
	}

	wantCharacters := 0
	for _, row := range wordmarkRows {
		wantCharacters += utf8.RuneCountInString(strings.ReplaceAll(row, " ", ""))
	}
	if checked != wantCharacters {
		t.Errorf("checked %d colored characters, want %d", checked, wantCharacters)
	}
}

func distinctColors(colors []rgb) map[rgb]bool {
	seen := make(map[rgb]bool)
	for _, color := range colors {
		seen[color] = true
	}

	return seen
}

func TestTheGradientWorksWithFewerColors(t *testing.T) {
	withProfile(t, termenv.ANSI256)

	lines := strings.Split(newModel("/work/project", nil).View(), "\n")
	for index, wantRow := range wordmarkRows {
		if got := styleCodes.ReplaceAllString(lines[index], ""); got != wantRow {
			t.Errorf("row %d: the text changed: %q", index, got)
		}
	}
	if !strings.Contains(lines[1], "38;5;") {
		t.Errorf("the 256-color codes are missing: %q", lines[1])
	}
}
