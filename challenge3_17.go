package crp

import (
	"errors"
)

func RepeatByte(b byte, n int) Bytes {
	ret := make(Bytes, n)
	for i := 0; i < n; i++ {
		ret[i] = b
	}
	return ret
}

func BreakCBCWithPaddingSideChannelLeak(cipher Bytes, iv Bytes, paddingValid func(Bytes) bool) (Bytes, error) {
	bs := 16

	if len(cipher) == 0 {
		return Bytes{}, errors.New("cipher is empty")
	}

	if len(cipher)%bs != 0 {
		return Bytes{}, errors.New("cipher does not have 16 byte blocks")
	}

	if !paddingValid(cipher) {
		return Bytes{}, errors.New("cipher does not have valid padding or paddingValid function is not working")
	}

	// Strategy:
	// Find the flip diff of each byte (starting with the last) in a block until the block has a valid padding
	// then only send the cipher up to the target block for validation

	blockCount := len(cipher) / bs

	// Find length of plaintext and padding
	// var paddingLength int
	//
	// for i := 0; i < bs; i++ {
	// 	lastBlockStart := (blockCount - 1) * bs
	//
	// 	testCipher := append(cipher, Bytes{}...)
	// 	testCipher[lastBlockStart+i] = testCipher[lastBlockStart+i] ^ byte(1)
	//
	// 	if !paddingValid(testCipher) {
	// 		paddingLength = bs - i
	// 		break
	// 	}
	// }
	//
	// plaintextLength := len(cipher) - paddingLength

	// Find plaintext

	var plaintextPadded Bytes

	for targetBlockIndex := 0; targetBlockIndex < blockCount; targetBlockIndex++ {
		var prevCipherBlock Bytes
		if targetBlockIndex == 0 {
			prevCipherBlock = iv
		} else {
			prevCipherBlock = cipher[(targetBlockIndex-1)*bs : (targetBlockIndex)*bs]
		}

		targetCipherBlock := append(Bytes{}, cipher[targetBlockIndex*bs:(targetBlockIndex+1)*bs]...)
		targetBlockDiffMask := make(Bytes, bs)

		for paddingLength := 1; paddingLength <= bs; paddingLength++ {
			testDiffMask := append(Bytes{}, targetBlockDiffMask...)
			for k := 1; k <= paddingLength-1; k++ {
				testDiffMask[bs-k] = testDiffMask[bs-k] ^ byte(k) ^ byte(paddingLength)
			}
			for j := byte(0); j <= 255; j++ {
				testDiffMask[bs-paddingLength] = byte(j)

				testCipher := append(testDiffMask, targetCipherBlock...)
				if paddingValid(testCipher) {
					targetBlockDiffMask[bs-paddingLength] = byte(j)
					if paddingLength == bs {
						finalDiff := XORBytes(testDiffMask, RepeatByte(byte(bs), bs))
						plaintextPadded = append(plaintextPadded, XORBytes(finalDiff, prevCipherBlock)...)
					}
					break
				}
				if j == 255 {
					panic("failed to find byte")
				}
			}
		}
	}

	return plaintextPadded.PKCS7Unpad(bs)
}
