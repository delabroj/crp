package crp_test

import (
	"log"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/delabroj/crp"
)

func TestHexXOR(t *testing.T) {
	cases := []struct {
		hex1   crp.Hex
		hex2   crp.Hex
		expXOR crp.Hex
	}{
		{
			hex1:   crp.Hex("1c0111001f010100061a024b53535009181c"),
			hex2:   crp.Hex("686974207468652062756c6c277320657965"),
			expXOR: crp.Hex("746865206b696420646f6e277420706c6179"),
		},
	}

	for _, tc := range cases {
		xor, err := crp.HexXOR(tc.hex1, tc.hex2)
		require.Nil(t, err)
		require.Equal(t, string(tc.expXOR), string(xor))

		message, _ := xor.Decode()
		log.Printf("Challenge 1.2 message: %v", string(message))
	}
}
