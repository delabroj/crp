package crp_test

import (
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestEncryptAESCBC(t *testing.T) {
	cases := []struct {
		name      string
		plaintext crp.Bytes
		key       crp.Bytes
		iv        crp.Bytes
		expError  bool
		expCipher crp.Bytes
	}{
		{
			name:      "ok",
			plaintext: crp.Bytes("secret message"),
			key:       crp.Bytes("secret keysecret"),
			iv:        crp.Bytes(strings.Repeat("\x00", 16)),
			expCipher: crp.Bytes("\xbb\v\xad\xb5\x15nQz\x98\x01>\x84O!j\x85"),
		},
		{
			name:      "no key",
			plaintext: crp.Bytes("secret message"),
			expError:  true,
		},
		{
			name:      "key wrong length",
			plaintext: crp.Bytes("secret message"),
			key:       crp.Bytes("s"),
			iv:        crp.Bytes(strings.Repeat("\x00", 16)),
			expError:  true,
		},
		{
			name:      "no vi",
			plaintext: crp.Bytes("secret message"),
			key:       crp.Bytes("secret keysecret"),
			expError:  true,
		},
		{
			name:      "vi wrong length",
			plaintext: crp.Bytes("secret message"),
			key:       crp.Bytes("secret keysecret"),
			iv:        crp.Bytes(strings.Repeat("\x00", 17)),
			expError:  true,
		},
	}

	bs := 16

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plaintextPadded, err := tc.plaintext.PKCS7Pad(bs)
			require.Nil(t, err)

			cipher, err := plaintextPadded.EncryptAESCBC(tc.key, tc.iv)
			require.Equal(t, tc.expError, err != nil)
			require.Equal(t, string(tc.expCipher), string(cipher))
		})
	}
}

func TestDecryptAESCBC(t *testing.T) {
	cases := []struct {
		name         string
		cipher       crp.Bytes
		key          crp.Bytes
		iv           crp.Bytes
		expError     bool
		expPlaintext crp.Bytes
	}{
		{
			name:         "ok",
			cipher:       crp.Bytes("\xbb\v\xad\xb5\x15nQz\x98\x01>\x84O!j\x85"),
			key:          crp.Bytes("secret keysecret"),
			iv:           crp.Bytes(strings.Repeat("\x00", 16)),
			expPlaintext: crp.Bytes("secret message"),
		},
		{
			name:     "no key",
			cipher:   crp.Bytes("secret message"),
			expError: true,
		},
		{
			name:     "key wrong length",
			cipher:   crp.Bytes("G\x17uCh\xf0\x8e\xd5g\x15+%H88\x92"),
			key:      crp.Bytes("s"),
			iv:       crp.Bytes(strings.Repeat("\x00", 16)),
			expError: true,
		},
		{
			name:     "no vi",
			cipher:   crp.Bytes("secret message"),
			key:      crp.Bytes("secret keysecret"),
			expError: true,
		},
		{
			name:     "vi wrong length",
			cipher:   crp.Bytes("secret message"),
			key:      crp.Bytes("secret keysecret"),
			iv:       crp.Bytes(strings.Repeat("\x00", 17)),
			expError: true,
		},
	}

	bs := 16

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plaintextPadded, err := tc.cipher.DecryptAESCBC(tc.key, tc.iv)
			require.Equal(t, tc.expError, err != nil)
			if err != nil {
				return
			}

			plaintext, _ := plaintextPadded.PKCS7Unpad(bs)
			require.Equal(t, string(tc.expPlaintext), string(plaintext))
		})
	}
}

func TestDecryptAESCBCMessage(t *testing.T) {
	rawCipherBase64, err := ioutil.ReadFile("./challenge2_10.txt")
	require.Nil(t, err)
	cipherBase64 := crp.Base64(strings.Replace(string(rawCipherBase64), "\n", "", -1))

	ciphertext, err := cipherBase64.Decode()
	require.Nil(t, err)

	key := crp.Bytes("YELLOW SUBMARINE")
	iv := crp.Bytes(strings.Repeat("\x00", 16))

	plaintext, err := ciphertext.DecryptAESCBC(key, iv)
	require.Nil(t, err)

	log.Printf("Challenge 2.10 message fragment:\n%v...", string(plaintext[:100]))

	ciphertext2, err := plaintext.EncryptAESCBC(key, iv)
	require.Nil(t, err)
	require.Equal(t, string(ciphertext), string(ciphertext2))
}
