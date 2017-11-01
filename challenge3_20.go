package crp

func BreakCRTSingleNonce(ciphers []Bytes) ([]Bytes, error) {
	var maxLength int
	for _, cipher := range ciphers {
		if len(cipher) > maxLength {
			maxLength = len(cipher)
		}
	}

	var keystream Bytes
	for i := 0; i < maxLength; i++ {
		var hopCipher Bytes
		for _, cipher := range ciphers {
			if len(cipher) >= i+1 {
				hopCipher = append(hopCipher, cipher[i])
			}
		}
		_, char, _, err := hopCipher.SingleCharHexXOR()
		if err != nil {
			return []Bytes{}, err
		}

		keystream = append(keystream, char...)
	}

	var plaintexts []Bytes
	for _, cipher := range ciphers {
		length := len(keystream)
		if length > len(cipher) {
			length = len(cipher)
		}
		plaintexts = append(plaintexts, XORBytes(cipher[:length], keystream[:length]))
	}

	return plaintexts, nil
}
