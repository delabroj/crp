package crp

import (
	"crypto/rand"
	"math/big"
	"strings"
)

func RandomBytes(n int) Bytes {
	b := make(Bytes, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func RandomBool() bool {
	b := make(Bytes, 1)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b[0]%2 == 0
}

func RandomInt(max int) int {
	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		panic(err)
	}
	return int(nBig.Int64())
}

func (p Bytes) EncryptECBorCBC(useECB bool) (Bytes, error) {
	key := RandomBytes(16)

	var paddedInput Bytes
	paddedInput = append(paddedInput, RandomBytes(RandomInt(6)+5)...)
	paddedInput = append(paddedInput, p...)
	paddedInput = append(paddedInput, RandomBytes(RandomInt(6)+5)...)
	paddedInput, err := paddedInput.PKCS7Pad(16)
	if err != nil {
		return Bytes{}, err
	}

	var cipher Bytes
	switch useECB {
	case true:
		cipher, err = paddedInput.EncryptAESECB(key)
		if err != nil {
			return Bytes{}, err
		}
	case false:
		iv := RandomBytes(16)
		cipher, err = paddedInput.EncryptAESCBC(key, iv)
		if err != nil {
			return Bytes{}, err
		}
	}
	return cipher, nil
}

func EncryptionOracle(encrypt func(Bytes) (Bytes, error)) (bool, error) {
	plaintext := Bytes(strings.Repeat("1234567890123456", 4))
	cipher, err := encrypt(plaintext)
	if err != nil {
		return false, err
	}
	repeatedBlocks := cipher.CountRepeatedBlocks()

	if repeatedBlocks[16] >= 2 {
		return true, nil
	}
	return false, nil
}
