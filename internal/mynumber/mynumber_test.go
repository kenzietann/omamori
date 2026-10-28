package mynumber

import "testing"

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
