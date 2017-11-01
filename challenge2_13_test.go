package crp_test

import (
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestQueryStringParse(t *testing.T) {
	cases := []struct {
		input     crp.QueryString
		expOutput map[string]string
	}{
		{
			input:     crp.QueryString("foo=bar&baz=qux&zap=zazzle"),
			expOutput: map[string]string{"foo": "bar", "baz": "qux", "zap": "zazzle"},
		},
		{
			input:     crp.QueryString("foo=bar&foo=qux&foo=zazzle"),
			expOutput: map[string]string{"foo": "bar"},
		},
	}

	for _, tc := range cases {
		output := tc.input.Parse()

		require.Equal(t, len(tc.expOutput), len(output))
		for k, v := range tc.expOutput {
			require.Equal(t, v, output[k])
		}
	}
}

func TestProfileFor(t *testing.T) {
	cases := []struct {
		email     string
		expOutput string
	}{
		{
			email:     "me@me.me",
			expOutput: "email=me@me.me&uid=10&role=user",
		},
		{
			email:     "me@me.me&role=admin",
			expOutput: "email=me@me.meroleadmin&uid=10&role=user",
		},
	}

	for _, tc := range cases {
		output := crp.GenerateProfile(tc.email)

		require.Equal(t, tc.expOutput, output)
	}
}

func TestCreateAdminProfile(t *testing.T) {
	bs := 16

	key := crp.RandomBytes(bs)

	generateEncryptedProfile := func(e string) (crp.Bytes, error) {
		plaintext := crp.Bytes(crp.GenerateProfile(e))

		plaintextPadded, err := plaintext.PKCS7Pad(bs)
		if err != nil {
			return crp.Bytes{}, err
		}

		return plaintextPadded.EncryptAESECB(key)
	}

	adminProfileCipher, err := crp.CreateAdminProfile(generateEncryptedProfile)
	require.Nil(t, err)

	adminProfile, err := adminProfileCipher.DecryptAESECB(key)
	require.Nil(t, err)

	adminProfileObject := crp.QueryString(string(adminProfile)).Parse()

	require.Equal(t, "admin", adminProfileObject["role"])
}
