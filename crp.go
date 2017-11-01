package crp

import (
	"encoding/base64"
	"encoding/hex"
)

type Hex []byte

func (h Hex) Decode() (Bytes, error) {
	p := make(Bytes, hex.DecodedLen(len(h)))
	_, err := hex.Decode(p, h)
	return p, err
}

type Base64 []byte

func (b Base64) Decode() (Bytes, error) {
	p := make(Bytes, base64.StdEncoding.DecodedLen(len(b)))
	_, err := base64.StdEncoding.Decode(p, b)
	for {
		if p[len(p)-1] != 0 {
			break
		}
		p = p[:len(p)-1]
	}
	return p, err
}

type Bytes []byte

func (p Bytes) EncodeHex() Hex {
	h := make(Hex, hex.EncodedLen(len(p)))
	hex.Encode(h, p)
	return h
}

func (p Bytes) EncodeBase64() Base64 {
	b := make(Base64, base64.StdEncoding.EncodedLen(len(p)))
	base64.StdEncoding.Encode(b, p)
	return b
}
