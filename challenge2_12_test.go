package crp_test

import (
	"log"
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestBreakECBWithPrefix(t *testing.T) {
	bs := 16

	unknownStringBase64 := crp.Base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	unknownString, err := unknownStringBase64.Decode()
	require.Nil(t, err)

	randomKey := crp.RandomBytes(bs)

	encryptWithPrefix := func(prefix crp.Bytes) (crp.Bytes, error) {
		plaintext := append(prefix, unknownString...)

		plaintextPadded, err := plaintext.PKCS7Pad(bs)
		if err != nil {
			return crp.Bytes{}, err
		}

		return plaintextPadded.EncryptAESECB(randomKey)
	}

	recoveredString, err := crp.BreakECBViaCustomPrefix(encryptWithPrefix)
	require.Nil(t, err)
	require.Equal(t, string(unknownString), string(recoveredString))

	log.Printf("Challenge 2.12 message:\n%v", string(recoveredString))
}
