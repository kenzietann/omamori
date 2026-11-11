package tui

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
	"github.com/muesli/termenv"
)

var styleCodes = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestMain(m *testing.M) {
	lipgloss.SetColorProfile(termenv.Ascii)
	lipgloss.SetHasDarkBackground(true)

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

func reverse(text string) string {
	runes := []rune(text)
	for from, to := 0, len(runes)-1; from < to; from, to = from+1, to-1 {
		runes[from], runes[to] = runes[to], runes[from]
	}

	return string(runes)
}

func TestIconAndWordmarkAreWellFormed(t *testing.T) {
	if len(iconPixels) != 28 {
		t.Errorf("the icon has %d pixel rows, want 28", len(iconPixels))
	}
	hasBlue := false
	for index, row := range iconPixels {
		if len(row) != 26 {
			t.Errorf("icon row %d is %d wide, want 26", index, len(row))
		}
		if row != reverse(row) {
			t.Errorf("icon row %d is not symmetric: %q", index, row)
		}
		if strings.Trim(row, ".LB") != "" {
			t.Errorf("icon row %d has an unknown pixel: %q", index, row)
		}
		hasBlue = hasBlue || strings.Contains(row, "B")
	}
	if !hasBlue {
		t.Error("the icon has no blue diamond")
	}

	for letter, rows := range glyphs {
		if len(rows) != 7 {
			t.Errorf("the letter %c has %d rows, want 7", letter, len(rows))
		}
		for _, row := range rows {
			if len(row) != len(rows[0]) || strings.Trim(row, ".#") != "" {
				t.Errorf("the letter %c has a bad row %q", letter, row)
			}
		}
	}

	wantWordmarkWidth := 6 // one gap between each pair of the 7 letters
	for _, letter := range "OMAMORI" {
		wantWordmarkWidth += len(glyphs[letter][0])
	}
	if len(wordmarkPixels) != 7 || len(wordmarkPixels[0]) != wantWordmarkWidth {
		t.Errorf("the wordmark is %d rows and %d wide", len(wordmarkPixels), len(wordmarkPixels[0]))
	}
	if logoWidth() > 80 {
		t.Errorf("the full logo is %d wide, it must fit 80 columns", logoWidth())
	}
}

func TestWithoutColorTheLogoIsPlainASCII(t *testing.T) {
	view := New("/work/project", nil).View()

	for _, character := range view {
		if character > unicode.MaxASCII {
			t.Errorf("the plain view holds %q", character)
		}
	}
	if strings.Contains(view, "\x1b") {
		t.Error("the plain view holds an escape code")
	}
	if !strings.Contains(view, "*") || !strings.Contains(view, "#") {
		t.Errorf("the ASCII logo is missing:\n%s", view)
	}
	if !strings.Contains(view, "a blue team helper with a guard") {
		t.Error("the tagline is missing")
	}
}

func TestWithoutColorTheWordmarkKeepsEveryPixelRow(t *testing.T) {
	view := New("/work/project", nil).View()

	toText := strings.NewReplacer("L", "#", ".", " ")
	for index, row := range wordmarkPixels {
		if !strings.Contains(view, strings.TrimRight(toText.Replace(row), " ")) {
			t.Errorf("the plain wordmark has no row for pixel row %d:\n%s", index, view)
		}
	}
}

func TestWithColorTheLogoUsesTheBrandColors(t *testing.T) {
	withProfile(t, termenv.TrueColor)

	view := New("/work/project", nil).View()

	for name, want := range map[string]string{
		"the blue diamond": "38;2;58;127;246",
		"the light body":   "38;2;231;237;246",
		"half blocks":      "▀",
		"full blocks":      "█",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("%s: the view has no %q", name, want)
		}
	}
}

func TestSmallWindowsGetAOneLineHeader(t *testing.T) {
	testCases := []struct {
		name   string
		width  int
		height int
	}{
		{"narrow", 60, 40},
		{"short", 100, 20},
		{"both", 50, 18},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			view := sized(New("/work/project", nil), testCase.width, testCase.height).View()

			if strings.ContainsAny(view, "#*") || !strings.Contains(view, "Omamori") {
				t.Errorf("the header is not the small one:\n%s", view)
			}
		})
	}

	large := sized(New("/work/project", nil), logoWidth(), minLogoHeight).View()
	if !strings.Contains(large, "#") {
		t.Error("a window that is exactly big enough did not get the full logo")
	}
}

func TestEveryLineFitsTheWindow(t *testing.T) {
	for _, profile := range []termenv.Profile{termenv.Ascii, termenv.TrueColor} {
		withProfile(t, profile)

		for _, size := range [][2]int{{80, 30}, {40, 30}, {20, 12}, {200, 50}} {
			home := sized(New("/very/long/folder/name/that/goes/on/and/on", finishedRunner("r", true)), size[0], size[1])
			running, command := press(t, home, "enter")
			results := sized(settle(running, command), size[0], size[1])

			for name, model := range map[string]Model{"home": home, "run": sized(running, size[0], size[1]), "results": results} {
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
	report := strings.Repeat("日本語のファイル名", 10)
	model, command := startedRun(t, finishedRunner(report, true))
	model = sized(settle(model, command), 30, 12)

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
	view := settle(model, command).View()

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
	if line := strings.Split(settle(incomplete, command).View(), "\n")[0]; !strings.Contains(line, "38;2;245;176;65") {
		t.Errorf("an incomplete result is not amber: %q", line)
	}
}

func TestOnlyOurStylingMakesEscapeCodes(t *testing.T) {
	withProfile(t, termenv.TrueColor)

	hostile := "a\x1b[999mred\x1b]0;title\x07 b‮evil c\x00d"
	runner := func(ctx context.Context, step func(string)) (Result, error) {
		step(hostile)
		return Result{Report: hostile, Complete: true}, nil
	}
	home := New(hostile, runner)
	running, command := press(t, home, "enter")
	results := settle(running, command)
	failed, failCommand := startedRun(t, func(ctx context.Context, step func(string)) (Result, error) {
		return Result{}, errors.New(hostile)
	})
	failed = settle(failed, failCommand)

	for name, model := range map[string]Model{"home": home, "run": running, "results": results, "error": failed} {
		view := model.View()

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
