package crp_test

import (
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestDecryptAESECB(t *testing.T) {
	rawCipherBase64, err := ioutil.ReadFile("./challenge1_7.txt")
	require.Nil(t, err)
	cipherBase64 := crp.Base64(strings.Replace(string(rawCipherBase64), "\n", "", -1))

	ciphertext, err := cipherBase64.Decode()
	require.Nil(t, err)

	key := crp.Bytes("YELLOW SUBMARINE")

	plaintext, err := ciphertext.DecryptAESECB(key)
	require.Nil(t, err)

	log.Printf("Challenge 1.7 message fragment:\n%v...", string(plaintext[:100]))

	ciphertext2, err := plaintext.EncryptAESECB(key)
	require.Nil(t, err)
	require.Equal(t, string(ciphertext), string(ciphertext2))
}
