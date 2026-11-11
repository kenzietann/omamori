package phone

import (
	"slices"
	"strings"
	"testing"
)

func TestFindPhoneNumbers(t *testing.T) {
	testCases := []struct {
		name        string
		inputText   string
		wantMatches []Match
	}{
		{"mobile with hyphens", "090-1234-5678", []Match{{0, 13}}},
		{"mobile plain", "09012345678", []Match{{0, 11}}},
		{"mobile with spaces", "090 1234 5678", []Match{{0, 13}}},
		{"mobile in a sentence", "call 090-1234-5678 now", []Match{{5, 18}}},
		{"IP phone 050", "050-1234-5678", []Match{{0, 13}}},
		{"Tokyo landline, 2-4-4", "03-1234-5678", []Match{{0, 12}}},
		{"landline 3-3-4", "045-123-4567", []Match{{0, 12}}},
		{"landline 4-2-4", "0422-12-3456", []Match{{0, 12}}},
		{"landline 5-1-4", "01234-5-6789", []Match{{0, 12}}},
		{"landline plain", "0312345678", []Match{{0, 10}}},
		{"toll-free 0120", "0120-123-456", []Match{{0, 12}}},
		{"toll-free 0800", "0800-123-4567", []Match{{0, 13}}},
		{"international with hyphens", "+81-90-1234-5678", []Match{{0, 16}}},
		{"international with spaces", "+81 90 1234 5678", []Match{{0, 16}}},
		{"international plain", "+819012345678", []Match{{0, 13}}},
		{"two numbers", "090-1234-5678 / 03-1234-5678", []Match{{0, 13}, {16, 28}}},
		{"letters touching", "tel090-1234-5678x", []Match{{3, 16}}},
		{"mixed separators", "090-1234 5678", nil},
		{"too short", "090-1234-567", nil},
		{"digit before", "1090-1234-5678", nil},
		{"digit after", "090-1234-56789", nil},
		{"11 digits with a landline start", "03123456789", nil},
		{"12 digits", "012345678901", nil},
		{"area code can not start with 00", "00-1234-5678", nil},
		{"other country code", "+82-90-1234-5678", nil},
		{"full-width digits and hyphens", "０９０\uFF0D１２３４\uFF0D５６７８", []Match{{0, 39}}},
		{"full-width digits, ASCII hyphens", "０９０-１２３４-５６７８", []Match{{0, 35}}},
		{"full-width digits in Japanese text", "電話は０９０\uFF0D１２３４\uFF0D５６７８です", []Match{{9, 48}}},
		{"prolonged sound mark as hyphen", "090\u30FC1234\u30FC5678", []Match{{0, 17}}},
		{"hyphen look-alike U+2010", "090\u20101234\u20105678", []Match{{0, 17}}},
		{"minus sign U+2212", "090\u22121234\u22125678", []Match{{0, 17}}},
		{"ideographic space", "090\u30001234\u30005678", []Match{{0, 17}}},
		{"dots", "090.1234.5678", []Match{{0, 13}}},
		{"area code in parentheses", "(03) 1234-5678", []Match{{0, 14}}},
		{"area code in parentheses, no space", "(03)1234-5678", []Match{{0, 13}}},
		{"mobile prefix in parentheses", "(090) 1234-5678", []Match{{0, 15}}},
		{"full-width parentheses", "\uFF0803\uFF09" + "1234-5678", []Match{{0, 17}}},
		{"international with (0)", "+81 (0)90-1234-5678", []Match{{0, 19}}},
		{"international with (0), plain", "+81(0)9012345678", []Match{{0, 16}}},
		{"full-width plus", "\uFF0B81 90 1234 5678", []Match{{0, 18}}},
		{"navi dial 0570", "0570-123-456", []Match{{0, 12}}},
		{"0180", "0180-123-456", []Match{{0, 12}}},
		{"0990", "0990-123-456", []Match{{0, 12}}},
		{"last digit full-width", "090-1234-567８", []Match{{0, 15}}},
		{"full-width digit before", "１090-1234-5678", nil},
		{"full-width digit after", "090-1234-5678９", nil},
		{"unbalanced parenthesis", "(03 1234-5678", nil},
		{"invalid UTF-8 byte inside", "090-12\xff4-5678", nil},
		{"empty text", "", nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotMatches := FindPhoneNumbers(testCase.inputText)

			if !slices.Equal(gotMatches, testCase.wantMatches) {
				t.Errorf("FindPhoneNumbers(%q) = %v, want %v", testCase.inputText, gotMatches, testCase.wantMatches)
			}
		})
	}
}

func findPhoneNumbersWholeText(text string) []Match {
	normalized := make([]byte, 0, len(text))
	byteOffsets := make([]int, 0, len(text)+1)

	for byteIndex, character := range text {
		normalized = append(normalized, normalizeCharacter(character))
		byteOffsets = append(byteOffsets, byteIndex)
	}
	byteOffsets = append(byteOffsets, len(text))

	var matches []Match

	for _, position := range phonePattern.FindAllIndex(normalized, -1) {
		start, end := position[0], position[1]

		if start > 0 && isASCIIDigit(normalized[start-1]) {
			continue
		}
		if end < len(normalized) && isASCIIDigit(normalized[end]) {
			continue
		}

		matches = append(matches, Match{Start: byteOffsets[start], End: byteOffsets[end]})
	}

	return matches
}

func TestRunByRunMatchesWholeText(t *testing.T) {
	inputTexts := []string{
		"",
		"090-1234-5678",
		"call 090-1234-5678 or 03-1234-5678 now",
		"0901234567890123",
		"1 090-1234-5678 9",
		"090-1234-5678\n090-1234-5678",
		"tel (03) 1234-5678 / +81 (0) 90 1234 5678",
		"１２３ 090-1234-5678９",
		"090 1234 5678 1234 5678 9012",
		"0 9 0 1 2 3 4 5 6 7 8",
		"2026-11-11 10:15:32 request 123456",
		"090-1234-56789 and 0312345678",
		strings.Repeat("0123456789 ", 50),
		strings.Repeat("a", 100) + "09012345678" + strings.Repeat("b", 100),
	}

	for _, inputText := range inputTexts {
		gotMatches := FindPhoneNumbers(inputText)
		wantMatches := findPhoneNumbersWholeText(inputText)

		if !slices.Equal(gotMatches, wantMatches) {
			t.Errorf("FindPhoneNumbers(%q) = %v, whole-text method gives %v", inputText, gotMatches, wantMatches)
		}
	}
}

func BenchmarkFindPhoneNumbers(b *testing.B) {
	line := "2026-11-11 10:15:32 INFO request id=123456 took 45ms from 192.168.0.12 本日の会議は午後三時です\n"
	benchmarkText := strings.Repeat(line, 10000)

	b.SetBytes(int64(len(benchmarkText)))
	for b.Loop() {
		FindPhoneNumbers(benchmarkText)
	}
}

func FuzzFindPhoneNumbers(f *testing.F) {
	f.Add("call 090-1234-5678 now")
	f.Add("+81 90 1234 5678")
	f.Add("03-1234-5678")
	f.Add("")

	f.Fuzz(func(t *testing.T, inputText string) {
		gotMatches := FindPhoneNumbers(inputText)
		wantMatches := findPhoneNumbersWholeText(inputText)

		if !slices.Equal(gotMatches, wantMatches) {
			t.Errorf("run-by-run gives %v, whole-text method gives %v", gotMatches, wantMatches)
		}
	})
}
