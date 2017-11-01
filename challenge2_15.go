package crp

func (b Bytes) PKCS7UnpadValidate() (Bytes, bool) {
	var ret Bytes
	var hadPadding bool

	for i := len(b) - 1; i > 0; i-- {
		if b[i] != 4 {
			ret = make(Bytes, len(b[:i+1]))
			copy(ret, b[:i+1])
			break
		}
		hadPadding = true
	}

	return ret, hadPadding
}
