package crp

func XORBytes(s1, s2 Bytes) Bytes {
	if len(s1) != len(s2) {
		panic("cannot xor slices of differing lengths")
	}

	ret := make(Bytes, len(s1))
	for i := range ret {
		ret[i] = s1[i] ^ s2[i]
	}

	return ret
}

func CBCProduceAdminCredentialViaBitflipping(encrptCBC func(Bytes) (Bytes, error)) (Bytes, error) {
	// Format is: "comment1=cooking%20MCs;userdata=" + input with '=' and ';' escaped + ";comment2=%20like%20a%20pound%20of%20bacon"
	// Prefix blocks: comment1=cooking %20MCs;userdata=

	innocentString := "myuserdata1"
	desiredString := ";admin=true"
	flipDiff := XORBytes(Bytes(innocentString), Bytes(desiredString))

	cipher, err := encrptCBC(Bytes(innocentString))

	// flip innocent string to desired string
	targetStart := 16
	targetSlice := cipher[targetStart : targetStart+len(flipDiff)]
	copy(targetSlice, XORBytes(targetSlice, flipDiff))

	return cipher, err
}
