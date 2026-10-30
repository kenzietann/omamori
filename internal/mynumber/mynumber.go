package mynumber

import "errors"

// Match says where a possible My Number sits in a text. It holds positions
// only, never the text itself, so a log or an error message can not leak the number.
// Start is the first byte. End is the byte after the last one, like text[Start:End].
type Match struct {
	Start int
	End   int
}

func CheckDigit(myNumber string) (int, error) {
	if len(myNumber) != 11 {
		return 0, errors.New("The inputted number digits is not 11")
	}

	digitsInArray := make([]int, len(myNumber))

	for k, char := range myNumber {
		if char < '0' || char > '9' {
			return 0, errors.New("Unsupported digits detected")
		}
		digitsInArray[k] = int(char - '0')
	}

	weights := [11]int{6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2}

	var summed int

	for i := range weights {
		summed += digitsInArray[i] * weights[i]
	}

	remainder := summed % 11

	if remainder == 0 || remainder == 1 {
		return 0, nil
	} else {
		return 11 - remainder, nil
	}
}

func Validate(inputDigits string) bool {
	if len(inputDigits) != 12 {
		return false
	}

	checkDigit, err := CheckDigit(inputDigits[:11])

	if err != nil {
		return false
	}

	if checkDigit == int(inputDigits[11]-'0') {
		return true
	}
	return false
}

func FindMyNumbers(text string) []Match {
	var characters []rune
	var byteOffsets []int
	var digitValues []int
	var matches []Match

	// Work on characters, not bytes, because a character can use more than one byte.
	// byteOffsets[i] is the byte where characters[i] starts. The last extra entry is
	// the end of the text, so a match at the very end can be turned back into bytes too.
	// digitValues[i] is 0 to 9 if characters[i] is a digit, ASCII (0-9) or
	// full-width (０-９). It is -1 for anything else.
	for byteIndex, character := range text {
		value := -1
		if character >= '0' && character <= '9' {
			value = int(character - '0')
		} else if character >= '０' && character <= '９' {
			value = int(character - '０')
		}

		characters = append(characters, character)
		byteOffsets = append(byteOffsets, byteIndex)
		digitValues = append(digitValues, value)
	}
	byteOffsets = append(byteOffsets, len(text))

	index := 0
	for index < len(characters) {
		startsWithDigit := digitValues[index] >= 0

		// A digit right before the start means we are in the middle of a longer number.
		digitBefore := index > 0 && digitValues[index-1] >= 0

		matchLength := 0 // in characters, not bytes

		if startsWithDigit && !digitBefore {
			length := 0

			// Plain form: 12 characters, like 123456789018.
			if index+12 <= len(characters) {
				length = 12
			}

			// Separated form: 14 characters, like 1234 5678 9018 or 1234-5678-9018.
			// Both separators must be the same, and they must be a normal space or hyphen.
			if index+14 <= len(characters) {
				firstSeparator := characters[index+4]
				secondSeparator := characters[index+9]

				if (firstSeparator == ' ' || firstSeparator == '-' || firstSeparator == '　') && firstSeparator == secondSeparator {
					length = 14
				}
			}

			// Collect the 12 digits as ASCII, because Validate wants ASCII digits.
			digits := make([]byte, 0, 12)
			allDigits := length > 0
			for offset := 0; offset < length; offset++ {
				if length == 14 && (offset == 4 || offset == 9) {
					continue // skip the two separators
				}

				value := digitValues[index+offset]
				if value < 0 {
					allDigits = false
					break
				}
				digits = append(digits, byte('0'+value))
			}

			// A digit right after the end means the number is longer than 12 digits.
			end := index + length
			digitAfter := end < len(characters) && digitValues[end] >= 0

			if allDigits && !digitAfter && Validate(string(digits)) {
				matchLength = length
			}
		}

		if matchLength > 0 {
			// Turn character positions back into byte positions.
			matches = append(matches, Match{Start: byteOffsets[index], End: byteOffsets[index+matchLength]})
			index += matchLength // jump past the match, so matches never overlap
		} else {
			index++
		}
	}

	return matches
}
