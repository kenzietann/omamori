package mynumber

import "errors"

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
		digitBefore := index > 0 && digitValues[index-1] >= 0
		matchLength := 0

		if startsWithDigit && !digitBefore {
			length := 0

			if index+12 <= len(characters) {
				length = 12
			}

			if index+14 <= len(characters) {
				firstSeparator := characters[index+4]
				secondSeparator := characters[index+9]

				if (firstSeparator == ' ' || firstSeparator == '-' || firstSeparator == '　') && firstSeparator == secondSeparator {
					length = 14
				}
			}

			digits := make([]byte, 0, 12)
			allDigits := length > 0
			for offset := 0; offset < length; offset++ {
				if length == 14 && (offset == 4 || offset == 9) {
					continue
				}

				value := digitValues[index+offset]
				if value < 0 {
					allDigits = false
					break
				}
				digits = append(digits, byte('0'+value))
			}

			end := index + length
			digitAfter := end < len(characters) && digitValues[end] >= 0

			if allDigits && !digitAfter && Validate(string(digits)) {
				matchLength = length
			}
		}

		if matchLength > 0 {
			matches = append(matches, Match{Start: byteOffsets[index], End: byteOffsets[index+matchLength]})
			index += matchLength
		} else {
			index++
		}
	}

	return matches
}
