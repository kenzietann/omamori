package mynumber

func CheckDigit(myNumber string) (int, error) {
	digitsInArray := make([]int, len(myNumber))

	for k, char := range myNumber {
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
