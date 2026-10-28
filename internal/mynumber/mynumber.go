package mynumber

import "errors"

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
