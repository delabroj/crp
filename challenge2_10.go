package crp

import (
	"errors"
	"fmt"
)

func (p Bytes) EncryptAESCBC(key Bytes, iv Bytes) (Bytes, error) {
	var ret Bytes

	bs := 16

	if len(p) == 0 {
		return Bytes{}, errors.New("plaintext must not be empty")
	}

	if len(key) == 0 {
		return Bytes{}, errors.New("key must not be empty")
	}

	if len(iv) != bs {
		return Bytes{}, fmt.Errorf("iv must be %d bytes long", bs)
	}

	numBlocks := len(p) / bs
	if len(p)%bs > 0 {
		numBlocks++
	}

	if len(p)%bs != 0 {
		return Bytes{}, errors.New("slice length must be a multiple of the blocksize")
	}

	if len(key)%bs != 0 {
		return Bytes{}, errors.New("key length must be a multiple of the blocksize")
	}

	prevCipherBlock := make(Bytes, bs)
	copy(prevCipherBlock, iv)

	for i := 0; i < numBlocks; i++ {
		pBlock := p[bs*i : bs*(i+1)]
		pBlockChained, err := pBlock.HexXOR(prevCipherBlock)
		if err != nil {
			return Bytes{}, err
		}

		cipherBlock, err := pBlockChained.EncryptAESECB(key)
		if err != nil {
			return Bytes{}, err
		}

		copy(prevCipherBlock, cipherBlock)

		ret = append(ret, cipherBlock...)
	}

	return ret, nil
}

func (c Bytes) DecryptAESCBC(key Bytes, iv Bytes) (Bytes, error) {
	var ret Bytes

	bs := 16

	if len(c) == 0 {
		return Bytes{}, errors.New("cipher must not be empty")
	}

	if len(key) != 16 {
		return Bytes{}, errors.New("key must be 16 bytes long")
	}

	if len(iv) != bs {
		return Bytes{}, fmt.Errorf("iv must be %d bytes long", bs)
	}

	numBlocks := len(c) / bs
	if len(c)%bs > 0 {
		numBlocks++
	}

	prevCipherBlock := make(Bytes, bs)
	copy(prevCipherBlock, iv)

	for i := 0; i < numBlocks; i++ {
		cBlock := c[bs*i : bs*(i+1)]
		pBlockChained, err := cBlock.DecryptAESECB(key)
		if err != nil {
			return Bytes{}, err
		}

		pBlock, err := pBlockChained.HexXOR(prevCipherBlock)
		if err != nil {
			return Bytes{}, err
		}

		copy(prevCipherBlock, cBlock)

		ret = append(ret, pBlock...)
	}

	return ret, nil
}
