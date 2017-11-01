package crp_test

import (
	"log"
	"strings"
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestBreakCBCWithBitflipping(t *testing.T) {
	bs := 16
	key := crp.RandomBytes(bs)
	iv := crp.RandomBytes(bs)

	prefix := crp.Bytes("comment1=cooking%20MCs;userdata=")
	suffix := crp.Bytes(";comment2=%20like%20a%20pound%20of%20bacon")

	encryptCBC := func(input crp.Bytes) (crp.Bytes, error) {
		inputString := strings.Replace(string(input), ";", "%3B", -1)
		inputString = strings.Replace(inputString, "=", "%3D", -1)

		plaintext := crp.Bytes(string(prefix) + inputString + string(suffix))
		// fmt.Println(string(plaintext))
		// fmt.Println(plaintext[32:48])

		plaintext, err := plaintext.PKCS7Pad(bs)
		if err != nil {
			return crp.Bytes{}, err
		}

		return plaintext.EncryptAESCBC(key, iv)
	}

	adminCredentialCipher, err := crp.CBCProduceAdminCredentialViaBitflipping(encryptCBC)
	require.Nil(t, err)

	adminCredentialPadded, err := adminCredentialCipher.DecryptAESCBC(key, iv)
	require.Nil(t, err)
	// fmt.Println(string(adminCredential))
	// fmt.Println(adminCredential[32:48])

	adminCredential, err := adminCredentialPadded.PKCS7Unpad(bs)
	require.Nil(t, err)

	require.True(t, strings.Contains(string(adminCredential), ";admin=true;"))

	log.Printf("Challenge 2.16 credential: %v", string(adminCredential))
}
