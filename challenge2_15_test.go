package crp_test

import (
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestPKCS7UnpadValidate(t *testing.T) {
	cases := []struct {
		input         crp.Bytes
		expOutput     crp.Bytes
		expHadPadding bool
	}{
		{
			input:         crp.Bytes("secret message\x04\x04"),
			expOutput:     crp.Bytes("secret message"),
			expHadPadding: true,
		},
		{
			input:         crp.Bytes("123\x04"),
			expOutput:     crp.Bytes("123"),
			expHadPadding: true,
		},
		{
			input:     crp.Bytes("123"),
			expOutput: crp.Bytes("123"),
		},
	}

	for _, tc := range cases {
		output, hadPadding := tc.input.PKCS7UnpadValidate()
		require.Equal(t, string(tc.expOutput), string(output))
		require.Equal(t, tc.expHadPadding, hadPadding)
	}
}
