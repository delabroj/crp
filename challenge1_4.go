package crp

import (
	"bufio"
	"math"
	"os"
)

func LinesFromFile(path string) (<-chan string, error) {
	ret := make(chan string)

	file, err := os.Open(path)
	if err != nil {
		close(ret)
		return ret, err
	}

	go func() {
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			ret <- scanner.Text()
		}
		close(ret)
	}()

	return ret, err
}

func SingleCharHexXORFromFile(path string) (int, Bytes, Bytes, error) {
	lines, err := LinesFromFile(path)
	if err != nil {
		return 0, Bytes{}, Bytes{}, err
	}

	minScore := math.MaxFloat64
	var minScoreLineNumber int
	var minScoreMessage Bytes
	var minScoreKey Bytes

	var lineNumber int
	for cipherRaw := range lines {
		lineNumber++
		cipherHex := Hex(cipherRaw)
		cipher, err := cipherHex.Decode()
		if err != nil {
			return 0, Bytes{}, Bytes{}, err
		}
		score, key, message, err := cipher.SingleCharHexXOR()
		if err != nil {
			return 0, Bytes{}, Bytes{}, err
		}
		if score < minScore {
			minScore = score
			minScoreLineNumber = lineNumber
			minScoreKey = key
			minScoreMessage = message
		}
	}
	return minScoreLineNumber, minScoreKey, minScoreMessage, nil
}
