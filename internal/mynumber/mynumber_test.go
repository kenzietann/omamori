package mynumber

import (
	"slices"
	"testing"
)

func TestCheckDigit(t *testing.T) {
	type checkDigitCase struct {
		name           string
		inputDigits    string
		wantCheckDigit int
	}

	testData := []checkDigitCase{
		{"E1", "12345678901", 8},
		{"descending", "09876543210", 3},
		{"Z01", "00000000000", 0},
		{"R1", "20000000000", 0},
		{"R10", "00000000005", 1},
		{"W01", "10000000000", 5},
		{"W02", "01000000000", 6},
		{"W03", "00100000000", 7},
		{"W04", "00010000000", 8},
		{"W05", "00001000000", 9},
		{"W06", "00000100000", 4},
		{"W07", "00000010000", 5},
		{"W08", "00000001000", 6},
		{"W09", "00000000100", 7},
		{"W10", "00000000010", 8},
		{"W11", "00000000001", 9},
	}

	for _, testCase := range testData {
		t.Run(testCase.name, func(t *testing.T) {
			gotCheckDigit, err := CheckDigit(testCase.inputDigits)

			if err != nil {
				t.Fatalf("CheckDigit(%q) returned an error: %v", testCase.inputDigits, err)
			}
			if gotCheckDigit != testCase.wantCheckDigit {
				t.Errorf("CheckDigit(%q) = %d, want %d", testCase.inputDigits, gotCheckDigit, testCase.wantCheckDigit)
			}
		})
	}
}

func TestBadInputs(t *testing.T) {
	testCases := []struct {
		name        string
		inputDigits string
		wantError   bool
	}{
		{"too short", "123", true},
		{"letter", "1234567890a", true},
		{"valid control", "12345678901", false},
		{"punctuation", "18'2332?.@,", true},
		{"empty", "", true},
		{"too long", "123456789012", true},
		{"space", "1234 678901", true},
		{"hyphen", "1234-678901", true},
		{"trailing newline", "1234567890\n", true},
		{"full-width digits", "１２３４５６７８９０１", true},
		{"Arabic-Indic digits", "١٢٣٤٥٦٧٨٩٠١", true},
		{"full-width digit, 11 bytes", "12345678９", true},
		{"Arabic-Indic digit, 11 bytes", "123456789١", true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := CheckDigit(testCase.inputDigits)
			gotError := err != nil
			if gotError != testCase.wantError {
				t.Errorf("CheckDigit(%q): got error = %v, want error = %v", testCase.inputDigits, gotError, testCase.wantError)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	testCases := []struct {
		name        string
		inputDigits string
		wantValid   bool
	}{
		{"V01", "123456789018", true},
		{"V02", "999999999996", true},
		{"V03", "000000000000", true},
		{"V04", "200000000000", true},
		{"V05", "000000000051", true},
		{"V06", "100000000005", true},
		{"V07", "000000000060", true},
		{"I01", "123456789019", false},
		{"I02", "223456789018", false},
		{"I03", "213456789018", false},
		{"I04", "000000000050", false},
		{"L01", "12345678901", false},
		{"L02", "1234567890180", false},
		{"L03", "", false},
		{"L04", "123456789018\n", false},
		{"N01", "12345678901A", false},
		{"N02", "1234 5678 9018", false},
		{"N03", "1234-5678-9018", false},
		{"N04", "１２３４５６７８９０１８", false},
		{"N05", "١٢٣٤٥٦٧٨٩٠١٨", false},
		{"N06", "12345678901８", false},
		{"12 bytes, Arabic-Indic digit", "1234567890١", false},
		{"12 bytes, full-width digit", "123456789０", false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotValid := Validate(testCase.inputDigits)

			if gotValid != testCase.wantValid {
				t.Errorf("Validate(%q) = %v, want %v", testCase.inputDigits, gotValid, testCase.wantValid)
			}
		})
	}
}

func FuzzValidate(f *testing.F) {
	f.Add("123456789018")

	f.Fuzz(func(t *testing.T, inputDigits string) {
		Validate(inputDigits)
	})
}

func TestFindMyNumbers(t *testing.T) {
	testCases := []struct {
		name        string
		inputText   string
		wantMatches []Match
	}{
		{"only the number", "123456789018", []Match{{0, 12}}},
		{"in a sentence", "id 123456789018 ok", []Match{{3, 15}}},
		{"with spaces", "1234 5678 9018", []Match{{0, 14}}},
		{"letters touching", "a123456789018b", []Match{{1, 13}}},
		{"13 digits", "1234567890180", nil},
		{"bad check digit", "123456789019", nil},
		{"mixed separators", "1234 5678-9018", nil},
		{"two numbers", "123456789018 and 999999999996", []Match{{0, 12}, {17, 29}}},
		{"empty text", "", nil},
		{"digit only after", "1234567890181", nil},
		{"digit only before", "0123456789018", nil},
		{"full-width digits", "１２３４５６７８９０１８", []Match{{0, 36}}},
		{"full-width in a sentence", "id １２３４５６７８９０１８ ok", []Match{{3, 39}}},
		{"full-width with spaces", "１２３４ ５６７８ ９０１８", []Match{{0, 38}}},
		{"full-width and ASCII mixed", "１２３４５６７８９０１8", []Match{{0, 34}}},
		{"full-width, digit after", "１２３４５６７８９０１８１", nil},
		{"full-width, digit before", "０１２３４５６７８９０１８", nil},
		{"full-width space", "1234　5678　9018", []Match{{0, 18}}},
		{"full-width space and digits", "１２３４　５６７８　９０１８", []Match{{0, 42}}},
		{"full-width space mixed with normal space", "1234　5678 9018", nil},
		{"full-width space, bad check digit", "1234　5678　9019", nil},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotMatches := FindMyNumbers(testCase.inputText)

			if !slices.Equal(gotMatches, testCase.wantMatches) {
				t.Errorf("FindMyNumbers(%q) = %v, want %v", testCase.inputText, gotMatches, testCase.wantMatches)
			}
		})
	}
}

func FuzzFindMyNumbers(f *testing.F) {
	f.Add("id 123456789018")
	f.Add("1234 5678 9018")
	f.Add("1234567890180")
	f.Add("")

	f.Fuzz(func(t *testing.T, inputText string) {
		FindMyNumbers(inputText)
	})
}
