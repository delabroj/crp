package crp

import (
	"crypto/aes"
	"errors"
)

func (b Bytes) EncryptAESECB(key Bytes) (Bytes, error) {
	var cipher Bytes

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	bs := block.BlockSize()
	if len(b)%bs != 0 {
		return Bytes{}, errors.New("slice length must be a multiple of the blocksize")
	}

	for i := 0; i < len(b); i += bs {
		cipherBlock := make(Bytes, bs)
		block.Encrypt(cipherBlock, b[i:i+bs])
		cipher = append(cipher, cipherBlock...)
	}

	return cipher, nil
}

func (b Bytes) DecryptAESECB(key Bytes) (Bytes, error) {
	var plaintext Bytes

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	bs := block.BlockSize()
	if len(b)%bs != 0 {
		return Bytes{}, errors.New("slice length must be a multiple of the blocksize")
	}

	for i := 0; i < len(b); i += bs {
		plaintextBlock := make(Bytes, bs)
		block.Decrypt(plaintextBlock, b[i:i+bs])
		plaintext = append(plaintext, plaintextBlock...)
	}

	return plaintext, nil
}
