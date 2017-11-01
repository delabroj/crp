package crp_test

import (
	"log"
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestEncryptAESCTR(t *testing.T) {
	cipherBase64 := crp.Base64("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	nonce := uint64(0)
	counter := uint64(0)
	key := crp.Bytes("YELLOW SUBMARINE")
	expPlaintext := crp.Bytes("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ")

	cipher, err := cipherBase64.Decode()
	require.Nil(t, err)

	plaintext, err := cipher.EncryptAESCTR(nonce, counter, key)
	require.Nil(t, err)
	require.Equal(t, string(expPlaintext), string(plaintext))

	cipher2, err := plaintext.EncryptAESCTR(nonce, counter, key)
	require.Nil(t, err)
	require.Equal(t, cipherBase64, cipher2.EncodeBase64())

	log.Printf("Challenge 3.18 message: %v", string(plaintext))
}
