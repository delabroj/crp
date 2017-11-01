package crp_test

import (
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestHexDecode(t *testing.T) {
	cases := []struct {
		hex     crp.Hex
		expText crp.Bytes
	}{
		{
			hex:     crp.Hex("736563726574206d657373616765"),
			expText: crp.Bytes("secret message"),
		},
	}

	for _, tc := range cases {
		text, err := tc.hex.Decode()
		require.Nil(t, err)
		require.Equal(t, string(tc.expText), string(text))
	}
}

func TestBase64Decode(t *testing.T) {
	cases := []struct {
		base64  crp.Base64
		expText crp.Bytes
	}{
		{
			base64:  crp.Base64("c2VjcmV0IG1lc3NhZ2U="),
			expText: crp.Bytes("secret message"),
		},
	}

	for _, tc := range cases {
		text, err := tc.base64.Decode()
		require.Nil(t, err)
		require.Equal(t, string(tc.expText), string(text))
	}
}

func TestHexEncode(t *testing.T) {
	cases := []struct {
		text   crp.Bytes
		expHex crp.Hex
	}{
		{
			text:   crp.Bytes("secret message"),
			expHex: crp.Hex("736563726574206d657373616765"),
		},
	}

	for _, tc := range cases {
		hex := tc.text.EncodeHex()
		require.Equal(t, string(tc.expHex), string(hex))
	}
}

func TestBase64Encode(t *testing.T) {
	cases := []struct {
		text      crp.Bytes
		expBase64 crp.Base64
	}{
		{
			text:      crp.Bytes("secret message"),
			expBase64: crp.Base64("c2VjcmV0IG1lc3NhZ2U="),
		},
	}

	for _, tc := range cases {
		base64 := tc.text.EncodeBase64()
		require.Equal(t, string(tc.expBase64), string(base64))
	}
}
