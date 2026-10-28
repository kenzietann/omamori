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
