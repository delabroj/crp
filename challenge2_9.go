package crp

import (
	"errors"
	"strings"
)

func (b Bytes) PKCS7Pad(bs int) (Bytes, error) {
	if bs < 1 || bs > 255 {
		return Bytes{}, errors.New("block size must be between 1 and 255 inclusive")
	}

	if len(b) == 0 {
		return Bytes{}, errors.New("cannot pad empty message")
	}

	// In PKCS7 the last block is padded with bytes whose value is equal to the number of padding bytes
	paddedBlockCount := (len(b) / bs) + 1

	paddingLength := paddedBlockCount*bs - len(b)
	paddingByte := byte(paddingLength)

	ret := make(Bytes, paddedBlockCount*bs)
	copy(ret, b)
	for i := len(b); i < paddingLength+len(b); i++ {
		ret[i] = paddingByte
	}

	return ret, nil
}

type InvalidPadding struct{}

func (i InvalidPadding) Error() string {
	return "invalid padding"
}

func (b Bytes) PKCS7Unpad(bs int) (Bytes, error) {
	var ret Bytes

	if len(b) == 0 {
		return Bytes{}, errors.New("cannot unpad empty string")
	}

	padByte := b[len(b)-1]
	if padByte == byte(0) {
		return Bytes{}, InvalidPadding{}
	}
	paddingLength := int(padByte)
	messageLength := len(b) - paddingLength

	if messageLength < 0 {
		return Bytes{}, InvalidPadding{}
	}

	if strings.Repeat(string(padByte), paddingLength) != string(b[messageLength:]) {
		return Bytes{}, InvalidPadding{}
	}

	ret = make(Bytes, messageLength)
	copy(ret, b[:messageLength])

	return ret, nil
}
