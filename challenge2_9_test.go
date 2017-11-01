package crp_test

import (
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestPKCS7Pad(t *testing.T) {
	cases := []struct {
		input     crp.Bytes
		bs        int
		expError  bool
		expOutput crp.Bytes
	}{
		{
			input:     crp.Bytes("123"),
			bs:        4,
			expOutput: crp.Bytes("123\x01"),
		},
		{
			input:     crp.Bytes("123"),
			bs:        3,
			expOutput: crp.Bytes("123\x03\x03\x03"),
		},
		{
			input:     crp.Bytes("1234567890"),
			bs:        16,
			expOutput: crp.Bytes("1234567890\x06\x06\x06\x06\x06\x06"),
		},
		{
			input:     crp.Bytes("secret message"),
			bs:        16,
			expOutput: crp.Bytes("secret message\x02\x02"),
		},
		{
			bs:       0,
			expError: true,
		},
		{
			bs:       256,
			expError: true,
		},
		{
			input:    crp.Bytes{},
			bs:       16,
			expError: true,
		},
	}

	for _, tc := range cases {
		output, err := tc.input.PKCS7Pad(tc.bs)
		require.Equal(t, tc.expError, err != nil)
		require.Equal(t, string(tc.expOutput), string(output))
	}
}

func TestPKCS7Unpad(t *testing.T) {
	cases := []struct {
		name      string
		input     crp.Bytes
		bs        int
		expError  error
		expOutput crp.Bytes
	}{
		{
			name:      "ok",
			input:     crp.Bytes("secret message\x02\x02"),
			bs:        16,
			expOutput: crp.Bytes("secret message"),
		},
		{
			name:      "ok - only padding",
			input:     crp.Bytes("\x01"),
			bs:        1,
			expOutput: crp.Bytes{},
		},
		{
			name:      "wrong padding byte",
			input:     crp.Bytes("123\x04"),
			bs:        4,
			expError:  crp.InvalidPadding{},
			expOutput: crp.Bytes{},
		},
		{
			name:     "no padding",
			input:    crp.Bytes("123"),
			bs:       3,
			expError: crp.InvalidPadding{},
		},
		{
			name:     "message doesn't fill last block",
			input:    crp.Bytes("123"),
			bs:       4,
			expError: crp.InvalidPadding{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := tc.input.PKCS7Unpad(tc.bs)
			require.Equal(t, tc.expError, err)
			require.Equal(t, string(tc.expOutput), string(output))
		})
	}
}
