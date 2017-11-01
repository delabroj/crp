package crp_test

import (
	"log"
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestHexXORMessage(t *testing.T) {
	cases := []struct {
		input     crp.Bytes
		key       crp.Bytes
		expOutput crp.Bytes
	}{
		{
			input:     crp.Bytes("secret message"),
			key:       crp.Bytes("A"),
			expOutput: crp.Bytes("2$\"3$5a,$22 &$"),
		},
		{
			input:     crp.Bytes("2$\"3$5a,$22 &$"),
			key:       crp.Bytes("A"),
			expOutput: crp.Bytes("secret message"),
		},
	}

	for _, tc := range cases {
		output, err := tc.input.HexXOR(tc.key)
		require.Nil(t, err)
		require.Equal(t, string(tc.expOutput), string(output))
	}
}

func TestSingleCharHexXOR(t *testing.T) {
	cipherHex := crp.Hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	cipher, err := cipherHex.Decode()
	require.Nil(t, err)

	_, key, plaintext, err := cipher.SingleCharHexXOR()
	require.Nil(t, err)

	log.Printf("Challenge 1.3 key: %v, message: %v", string(key), string(plaintext))
}
