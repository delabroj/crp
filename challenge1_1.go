package crp

func HexToBase64(h Hex) (Base64, error) {
	bytes, err := h.Decode()
	if err != nil {
		return Base64{}, err
	}
	return bytes.EncodeBase64(), nil
}
