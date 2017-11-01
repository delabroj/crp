package crp_test

import (
	"log"
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestLinesFromFile(t *testing.T) {
	cases := []struct {
		path     string
		expError bool
		expLines int
	}{
		{
			path:     "./doesntexist.txt",
			expError: true,
		},
		{
			path:     "./challenge1_4.txt",
			expError: false,
			expLines: 327,
		},
	}

	for _, tc := range cases {
		lines, err := crp.LinesFromFile(tc.path)
		require.Equal(t, tc.expError, err != nil)

		var count int
		for line := range lines {
			_ = line
			count++
		}
		require.Equal(t, tc.expLines, count)
	}
}

func TestSingleCharHexXORFromFile(t *testing.T) {
	path := "./challenge1_4.txt"
	lineNumber, key, message, err := crp.SingleCharHexXORFromFile(path)
	require.Nil(t, err)

	log.Printf("Challenge 1.4 line number: %d, key: %v, message: %v", lineNumber, string(key), string(message))
}
