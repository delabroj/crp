package crp

import (
	"encoding/binary"
	"errors"
	"math"
)

func (b Bytes) EncryptMT19937(seed uint16) Bytes {
	ret := make(Bytes, len(b))

	mt := NewMT19937(uint32(seed))
	var pad Bytes
	for i := range b {
		if i%4 == 0 {
			pad = make(Bytes, 4)
			binary.BigEndian.PutUint32(pad, mt.ExtractUint32())
		}

		ret[i] = b[i] ^ pad[i%4]
	}

	return ret
}

func RecoverEncrypt19937Key(encryptWithRandomPrefix func(Bytes) Bytes) (uint16, error) {
	plaintextSuffix := RepeatByte(byte(0), 7)
	cipher := encryptWithRandomPrefix(plaintextSuffix)

	for i := 0; i < math.MaxUint16; i++ {
		testPlaintext := append(RepeatByte(byte(0), len(cipher)-7), plaintextSuffix...)
		testCipher := testPlaintext.EncryptMT19937(uint16(i))
		if string(testCipher[len(cipher)-4:]) == string(cipher[len(cipher)-4:]) {
			return uint16(i), nil
		}
	}

	return 0, errors.New("could not find seed")
}
