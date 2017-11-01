package crp

import (
	"math"
	"strings"
)

func repeatingKey(key Hex, length int) Hex {
	ret := make(Hex, length)
	for i := 0; i < length; i++ {
		ret[i] = key[i%len(key)]
	}
	return ret
}

func (input Bytes) HexXOR(key Bytes) (Bytes, error) {
	inputHex := input.EncodeHex()
	keyHex := key.EncodeHex()
	expandedKey := repeatingKey(keyHex, len(inputHex))
	outputHex, err := HexXOR(inputHex, expandedKey)
	if err != nil {
		return Bytes{}, err
	}
	output, err := outputHex.Decode()
	if err != nil {
		return Bytes{}, err
	}
	return output, nil
}

func (b Bytes) Score() float64 {
	expCharFreq := map[rune]float64{
		'a': .082, 'b': .014, 'c': .028, 'd': .043, 'e': .127, 'f': .022, 'g': .020,
		'h': .061, 'i': .070, 'j': .002, 'k': .008, 'l': .040, 'm': .024, 'n': .067,
		'o': .075, 'p': .019, 'q': .001, 'r': .069, 's': .063, 't': .091, 'u': .028,
		'v': .010, 'w': .024, 'x': .002, 'y': .020, 'z': .001, ' ': .192,
		',': 0, ';': 0, ':': 0, '!': 0, '?': 0, '\'': 0, '"': 0, '-': 0,
	}

	charFreq := make(map[rune]float64)
	for _, char := range string(b) {
		charFreq[char]++
	}
	for k := range charFreq {
		charFreq[k] /= float64(len(string(b)))
	}

	usedChars := make(map[rune]struct{})

	var sum float64
	for k, v := range expCharFreq {
		usedChars[k] = struct{}{}
		sum += (v - charFreq[k]) * (v - charFreq[k])
	}

	// Penalize characters that aren't in expCharFreq
	for k, v := range charFreq {
		if _, ok := expCharFreq[k]; ok {
			continue
		}
		sum += 10 * v * v
	}

	return math.Sqrt(sum)
}

func (input Bytes) SingleCharHexXOR() (float64, Bytes, Bytes, error) {
	minScore := math.MaxFloat64
	var minScoreOutput Bytes
	var minScoreKey Bytes

	for i := 0; i <= 255; i++ {
		key := Bytes{byte(i)}
		output, err := input.HexXOR(key)
		if err != nil {
			return 0, Bytes{}, Bytes{}, err
		}

		outputLower := Bytes(strings.ToLower(string(output)))

		score := outputLower.Score()
		if score < minScore {
			minScore = score
			minScoreOutput = output
			minScoreKey = key
		}
	}
	return minScore, minScoreKey, minScoreOutput, nil
}
