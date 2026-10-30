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
	var matches []Match

	index := 0
	for index < len(text) {
		startsWithDigit := text[index] >= '0' && text[index] <= '9'

		digitBefore := index > 0 && text[index-1] >= '0' && text[index-1] <= '9'

		matchLength := 0

		if startsWithDigit && !digitBefore {
			digits := ""
			length := 0

			if index+12 <= len(text) {
				digits = text[index : index+12]
				length = 12
			}

			if index+14 <= len(text) {
				firstSeparator := text[index+4]
				secondSeparator := text[index+9]

				if (firstSeparator == ' ' || firstSeparator == '-') && firstSeparator == secondSeparator {
					digits = text[index:index+4] + text[index+5:index+9] + text[index+10:index+14]
					length = 14
				}
			}

			allDigits := len(digits) == 12
			for position := 0; position < len(digits); position++ {
				if digits[position] < '0' || digits[position] > '9' {
					allDigits = false
				}
			}

			end := index + length
			digitAfter := end < len(text) && text[end] >= '0' && text[end] <= '9'

			if allDigits && !digitAfter && Validate(digits) {
				matchLength = length
			}
		}

		if matchLength > 0 {
			matches = append(matches, Match{Start: index, End: index + matchLength})
			index += matchLength
		} else {
			index++
		}
	}

	return matches
}
