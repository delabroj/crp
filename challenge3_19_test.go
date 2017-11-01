package crp_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func _TestManualBreakCTRSingleNonce(t *testing.T) {
	path := "./challenge3_19.txt"

	lines, err := crp.LinesFromFile(path)
	require.Nil(t, err)

	key := crp.Bytes("random key 12345")

	var ciphers []crp.Bytes
	var lengths []int
	var maxLength int
	var longestCipherIndex int
	var i int
	for line := range lines {
		plaintextBase64 := crp.Base64(line)
		plaintext, err := plaintextBase64.Decode()
		require.Nil(t, err)

		cipher, err := plaintext.EncryptAESCTR(0, 0, key)
		require.Nil(t, err)

		ciphers = append(ciphers, cipher)
		lengths = append(lengths, len(cipher))

		if len(cipher) > maxLength {
			maxLength = len(cipher)
			longestCipherIndex = i
		}
		i++
	}
	// fmt.Println("maxLength = ", maxLength) // found to be 38
	// fmt.Println("longestCipherIndex = ", longestCipherIndex) // found to be 37

	// Strategy: Start with empty string and construct guess of chosen plaintext until all ciphers are decrypted
	// First find all spaces in longest cipher, find the other characters by finding other ciphers that have spaces at each index
	// 	12345678901234567890123456789012345678
	//  *e, too, has been changed in his turn, (last two characters found via web search)
	// guessIndex := 4
	// guessPlaintext := crp.Bytes(strings.Repeat("d", 36))
	//
	// guessLength := len(guessPlaintext)
	// keystreamGuess := crp.XORBytes(ciphers[guessIndex][:guessLength], guessPlaintext)
	//
	// for i, cipher := range ciphers {
	// 	length := len(cipher)
	// 	if length > guessLength {
	// 		length = guessLength
	// 	}
	// 	plaintext := string(crp.XORBytes(cipher[:length], keystreamGuess[:length]))
	// 	if len(plaintext) == guessLength {
	// 		fmt.Printf("%.2d: '%v'\n", i, string(plaintext[guessLength-1]))
	// 	}
	// }

	longestPlaintext := crp.Bytes("He, too, has been changed in his turn,")
	keystream := crp.XORBytes(ciphers[longestCipherIndex], longestPlaintext)

	log.Println("Challenge 3.19 message:")
	for i, cipher := range ciphers {
		length := len(cipher)
		plaintext := string(crp.XORBytes(cipher[:length], keystream[:length]))
		fmt.Printf("%.2d: %v\n", i, string(plaintext))
	}
}
