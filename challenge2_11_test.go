package crp_test

import (
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestRandomBytes(t *testing.T) {
	length := 1000
	b := crp.RandomBytes(length)

	byteCount := make(map[byte]int)

	for _, v := range b {
		byteCount[v]++
	}

	require.True(t, len(byteCount) > 200)
}

func TestEncryptionOracle(t *testing.T) {
	cases := []struct {
		name      string
		expUseECB bool
	}{
		{
			name:      "ECB",
			expUseECB: true,
		},
		{
			name:      "CBC",
			expUseECB: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encrypt := func(p crp.Bytes) (crp.Bytes, error) {
				return p.EncryptECBorCBC(tc.expUseECB)
			}
			useECB, err := crp.EncryptionOracle(encrypt)
			require.Nil(t, err)
			require.Equal(t, tc.expUseECB, useECB)
		})
	}
}

//
// func TestDecryptAESCBCMessage(t *testing.T) {
// 	rawCipherBase64, err := ioutil.ReadFile("./challenge2_10.txt")
// 	require.Nil(t, err)
// 	cipherBase64 := crp.Base64(strings.Replace(string(rawCipherBase64), "\n", "", -1))
//
// 	ciphertext, err := cipherBase64.Decode()
// 	require.Nil(t, err)
//
// 	key := crp.Bytes("YELLOW SUBMARINE")
// 	iv := crp.Bytes(strings.Repeat("\x00", 16))
//
// 	plaintext, err := ciphertext.DecryptAESCBC(key, iv)
// 	require.Nil(t, err)
//
// 	log.Printf("Challenge 2.10 message fragment:\n%v...", string(plaintext[:100]))
//
// 	ciphertext2, err := plaintext.EncryptAESCBC(key, iv)
// 	require.Nil(t, err)
// 	require.Equal(t, string(ciphertext), string(ciphertext2))
// }
