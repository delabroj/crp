package crp_test

import (
	"log"
	"testing"
	"time"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestEncryptMT19937(t *testing.T) {
	expPlaintext := crp.Bytes("this is my super secret message")
	seed := uint16(time.Now().UnixNano())
	cipher := expPlaintext.EncryptMT19937(seed)

	plaintext := cipher.EncryptMT19937(seed)
	require.Equal(t, string(expPlaintext), string(plaintext))
}

func TestRecoverEncrypt19937Key(t *testing.T) {
	expSeed := uint16(time.Now().UnixNano())

	encryptWithPrefix := func(b crp.Bytes) crp.Bytes {
		prefix := crp.RandomBytes(5 + int(time.Now().UnixNano()%32))
		plaintext := append(prefix, b...)
		return plaintext.EncryptMT19937(expSeed)
	}

	seed, err := crp.RecoverEncrypt19937Key(encryptWithPrefix)
	require.Nil(t, err)
	require.Equal(t, expSeed, seed)

	log.Println("Challenge 3.24 seed:", seed)
}
