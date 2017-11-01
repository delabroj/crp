package crp

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

func (b Bytes) EncryptAESCTR(nonce, counter uint64, key Bytes) (Bytes, error) {
	ret := make(Bytes, len(b))
	bs := 16

	if len(key) != bs {
		return Bytes{}, errors.New("key must be 16 bytes long")
	}

	nonceB := make(Bytes, 8)
	binary.LittleEndian.PutUint64(nonceB, nonce)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	var nonceAndCounter Bytes
	var pad Bytes
	for i := range b {
		if i%bs == 0 {
			counterB := make(Bytes, 8)
			binary.LittleEndian.PutUint64(counterB, counter+uint64(i/bs))

			nonceAndCounter = append(nonceB, counterB...)
			pad = make(Bytes, bs)
			block.Encrypt(pad, nonceAndCounter)
		}

		ret[i] = b[i] ^ pad[i%bs]
	}

	return ret, nil
}
