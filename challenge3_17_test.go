package crp_test

import (
	"fmt"
	"log"
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func _TestBreakCBCWithPaddingSideChannelLeak(t *testing.T) {
	cases := []struct {
		plainTextBase64 crp.Base64
	}{
		{plainTextBase64: crp.Base64("MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=")},
		{plainTextBase64: crp.Base64("MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=")},
		{plainTextBase64: crp.Base64("MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==")},
		{plainTextBase64: crp.Base64("MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==")},
		{plainTextBase64: crp.Base64("MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl")},
		{plainTextBase64: crp.Base64("MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==")},
		{plainTextBase64: crp.Base64("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==")},
		{plainTextBase64: crp.Base64("MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=")},
		{plainTextBase64: crp.Base64("MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=")},
		{plainTextBase64: crp.Base64("MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93")},
	}

	bs := 16

	log.Println("Challenge 3.17 messages:")

	for _, tc := range cases {
		expPlaintext, err := tc.plainTextBase64.Decode()
		require.Nil(t, err)

		expPlainTextPadded, err := expPlaintext.PKCS7Pad(bs)
		require.Nil(t, err)

		key := crp.RandomBytes(bs)
		iv := crp.RandomBytes(bs)

		cipher, err := expPlainTextPadded.EncryptAESCBC(key, iv)
		require.Nil(t, err)

		paddingValid := func(cipher crp.Bytes) bool {
			plaintextPadded, err := cipher.DecryptAESCBC(key, iv)
			if err != nil {
				return false
			}

			_, err = plaintextPadded.PKCS7Unpad(bs)
			return err == nil
		}

		plaintext, err := crp.BreakCBCWithPaddingSideChannelLeak(cipher, iv, paddingValid)
		require.Nil(t, err)
		require.Equal(t, string(expPlaintext), string(plaintext))

		fmt.Printf("%v\n", string(plaintext))
	}
}
