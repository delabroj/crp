package crp_test

import (
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestHexXORMessageLongKey(t *testing.T) {
	cases := []struct {
		input        crp.Bytes
		key          crp.Bytes
		expOutputHex crp.Hex
	}{
		{
			input:        crp.Bytes("Burning 'em, if you ain't quick and nimble"),
			key:          crp.Bytes("ICE"),
			expOutputHex: crp.Hex("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20"),
		},
		{
			input:        crp.Bytes("I go crazy when I hear a cymbal"),
			key:          crp.Bytes("ICE"),
			expOutputHex: crp.Hex("0063222663263b223f30633221262b690a652126243b632469203c24212425"),
		},
	}

	for _, tc := range cases {
		output, err := tc.input.HexXOR(tc.key)
		require.Nil(t, err)
		outputHex := output.EncodeHex()
		require.Equal(t, string(tc.expOutputHex), string(outputHex))
	}
}
