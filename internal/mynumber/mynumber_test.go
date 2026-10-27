package mynumber

import "testing"

func TestCheckDigit(t *testing.T) {
	want := 8

	got, err := CheckDigit("12345678901")

	if err != nil {
		t.Fatalf("CheckDigit returned an error: %v", err)
	}
	if got != want {
		t.Errorf("CheckDigit(...) = %d, want %d", got, want)
	}
}
