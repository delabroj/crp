package crp

import (
	"errors"
	"sort"
)

func HammingDistance(s1, s2 []byte) (int, error) {
	if len(s1) != len(s2) {
		return 0, errors.New("slices must be the same length")
	}

	distance := 0

	for i := range s1 {
		for j := uint(0); j < 8; j++ {
			mask := byte(1 << j)
			if (s1[i] & mask) != (s2[i] & mask) {
				distance++
			}
		}
	}

	return distance, nil
}

func (b Bytes) FindXORKeyLength() ([]int, error) {
	maxKeyLength := 40

	avgNormDistances := make(map[int]float64)

	for keyLength := 2; keyLength <= 5*maxKeyLength; keyLength++ {
		if 2*keyLength > len(b) {
			break
		}

		numBlocks := len(b) / keyLength
		keyLengthCount := len(b) / keyLength
		if numBlocks > keyLengthCount {
			numBlocks = keyLengthCount
		}

		var blocks []Bytes
		for i := 0; i < numBlocks; i++ {
			blocks = append(blocks, b[keyLength*i:keyLength*(i+1)])
		}

		var sum float64
		var count int
		for i := 0; i < numBlocks-1; i++ {
			distance, err := HammingDistance(blocks[i], blocks[i+1])
			if err != nil {
				return []int{}, err
			}
			normDistance := float64(distance) / float64(keyLength)
			sum += normDistance
			count++
		}
		avgNormDistances[keyLength] = sum / float64(count)
	}

	keyLengthScores := make(map[int]float64)
	for k, _ := range avgNormDistances {
		if k > maxKeyLength {
			continue
		}
		var sum float64
		var count int
		for i := k; i <= 2*maxKeyLength; i += k {
			avg := (avgNormDistances[i-1] + avgNormDistances[i] + avgNormDistances[i+1]) / float64(3)
			sum += (avg - avgNormDistances[i]) / avg
			count++
		}
		keyLengthScores[k] = sum / float64(count)
	}

	type keyLengthScoreStruct struct {
		keyLength int
		score     float64
	}

	var keyLengthScoreSlice []keyLengthScoreStruct

	for k, v := range keyLengthScores {
		keyLengthScoreSlice = append(keyLengthScoreSlice, keyLengthScoreStruct{keyLength: k, score: v})
	}

	sort.Slice(keyLengthScoreSlice, func(i, j int) bool { return keyLengthScoreSlice[i].score > keyLengthScoreSlice[j].score })

	var cutoff int
	for i := 0; i < len(keyLengthScoreSlice); i++ {
		if keyLengthScoreSlice[i].score < keyLengthScoreSlice[0].score*.5 {
			cutoff = i
			break
		}
	}
	var ret []int
	ret = append(ret, keyLengthScoreSlice[0].keyLength)

	sort.Slice(keyLengthScoreSlice[:cutoff], func(i, j int) bool { return keyLengthScoreSlice[i].keyLength < keyLengthScoreSlice[j].keyLength })

	for i, v := range keyLengthScoreSlice[:cutoff] {
		if i == 2 || v.keyLength == ret[0] {
			break
		}
		ret = append(ret, keyLengthScoreSlice[i].keyLength)
	}

	return ret, nil
}

func (b Bytes) FindXORKey(keyLength int) (Bytes, error) {
	key := make(Bytes, keyLength)

	for i, _ := range key {
		var hopCipher Bytes
		for j := i; j < len(b); j += keyLength {
			hopCipher = append(hopCipher, b[j])
		}

		_, keyChar, _, err := hopCipher.SingleCharHexXOR()
		if err != nil {
			return Bytes{}, err
		}
		key[i] = keyChar[0]
	}

	return key, nil
}
