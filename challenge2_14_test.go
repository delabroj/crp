package crp_test

import (
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestFindLengthOfECBPrefix(t *testing.T) {
	bs := 16

	unknownStringBase64 := crp.Base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	unknownString, err := unknownStringBase64.Decode()
	require.Nil(t, err)

	for i := 0; i < 5*256; i++ {
		randomKey := crp.RandomBytes(bs)

		padding := crp.RandomBytes(i)

		encryptWithRoot := func(root crp.Bytes) (crp.Bytes, error) {
			plaintext := append(padding, append(root, unknownString...)...)

			plaintextPadded, err := plaintext.PKCS7Pad(bs)
			if err != nil {
				return crp.Bytes{}, err
			}

			return plaintextPadded.EncryptAESECB(randomKey)
		}

		prefixLength, err := crp.FindLengthOfECBPrefix(encryptWithRoot)
		require.Nil(t, err)

		// if i != prefixLength {
		// 	fmt.Printf("%v - %v\n", i, prefixLength)
		// }
		require.Equal(t, i, prefixLength)
	}
}

func TestBreakECBWithRootAndPadding(t *testing.T) {
	bs := 16

	unknownStringBase64 := crp.Base64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	unknownString, err := unknownStringBase64.Decode()
	require.Nil(t, err)

	randomKey := crp.RandomBytes(bs)

	randomInt := crp.RandomInt(1000)
	padding := crp.RandomBytes(randomInt)

	encryptWithRoot := func(root crp.Bytes) (crp.Bytes, error) {
		plaintext := append(padding, append(root, unknownString...)...)

		plaintextPadded, err := plaintext.PKCS7Pad(bs)
		if err != nil {
			return crp.Bytes{}, err
		}

		return plaintextPadded.EncryptAESECB(randomKey)
	}

	recoveredString, err := crp.BreakECBViaCustomRoot(encryptWithRoot)
	require.Nil(t, err)
	require.Equal(t, string(unknownString), string(recoveredString))
}
