package crp_test

import (
	"log"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/delabroj/crp"
)

func TestHexToBase64(t *testing.T) {
	cases := []struct {
		hex       crp.Hex
		expBase64 crp.Base64
	}{
		{
			hex:       crp.Hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
			expBase64: crp.Base64("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"),
		},
	}

	for _, tc := range cases {
		base64, err := crp.HexToBase64(tc.hex)
		require.Nil(t, err)
		require.Equal(t, string(tc.expBase64), string(base64))

		message, _ := base64.Decode()
		log.Printf("Challenge 1.1 message: %v", string(message))
	}
}
