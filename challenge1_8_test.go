package crp_test

import (
	"log"
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestFindRepeatingBlocks(t *testing.T) {
	cases := []struct {
		b                  crp.Bytes
		expRepeatingBlocks map[int]int
	}{
		{
			b:                  crp.Bytes("123abc123123"),
			expRepeatingBlocks: map[int]int{2: 1, 3: 2},
		},
	}

	for _, tc := range cases {
		repeatingBlocks := tc.b.CountRepeatedBlocks()

		require.Equal(t, len(tc.expRepeatingBlocks), len(repeatingBlocks))
		for k, v := range tc.expRepeatingBlocks {
			require.Equal(t, v, repeatingBlocks[k])
		}
	}
}

func TestDecodeAESECBEncryptedLine(t *testing.T) {
	path := "./challenge1_8.txt"

	lines, err := crp.LinesFromFile(path)
	require.Nil(t, err)

	var lineNumber int

	var maxRepeatedBlockCount int

	targetLine := struct {
		lineNumber     int
		repeatedBlocks map[int]int
	}{}
	for lineRaw := range lines {
		lineNumber++
		lineHex := crp.Hex(lineRaw)

		lineB, err := lineHex.Decode()
		require.Nil(t, err)

		repeatedBlocks := lineB.CountRepeatedBlocks()

		var count int
		for _, v := range repeatedBlocks {
			count += v
		}

		if count > maxRepeatedBlockCount {
			maxRepeatedBlockCount = count
			targetLine.lineNumber = lineNumber
			targetLine.repeatedBlocks = repeatedBlocks
		}
	}

	log.Printf("Challenge 1.8 line: %v, repeated blocks: %v", targetLine.lineNumber, targetLine.repeatedBlocks)
}
