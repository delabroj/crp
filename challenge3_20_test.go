package crp_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestBreakCTRSingleNonce(t *testing.T) {
	path := "./challenge3_20.txt"

	lines, err := crp.LinesFromFile(path)
	require.Nil(t, err)

	key := crp.Bytes("random key 12345")

	var ciphers []crp.Bytes
	for line := range lines {
		plaintextBase64 := crp.Base64(line)
		plaintext, err := plaintextBase64.Decode()
		require.Nil(t, err)

		cipher, err := plaintext.EncryptAESCTR(0, 0, key)
		require.Nil(t, err)

		ciphers = append(ciphers, cipher)
	}

	plaintexts, err := crp.BreakCRTSingleNonce(ciphers)
	require.Nil(t, err)

	log.Println("Challenge 3.20 message:")
	for i, plaintext := range plaintexts {
		fmt.Printf("%.2d: %v\n", i, string(plaintext))
	}
}
