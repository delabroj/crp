package crp

import (
	"errors"
	"fmt"
	"strings"
)

func BreakECBViaCustomPrefix(encryptWithPrefix func(Bytes) (Bytes, error)) (Bytes, error) {
	As := func(n int) Bytes {
		return Bytes(strings.Repeat("A", n))
	}

	// Find block size and padding length
	var bs int
	var paddingLength int

	cipher, err := encryptWithPrefix(Bytes{})
	if err != nil {
		return Bytes{}, err
	}
	noPrefixLength := len(cipher)

	for i := 1; i <= 16; i++ {
		prefix := As(i)
		cipher, err := encryptWithPrefix(prefix)
		if err != nil {
			return Bytes{}, err
		}
		if len(cipher) != noPrefixLength {
			bs = len(cipher) - noPrefixLength
			paddingLength = i
			break
		}

		if i == 16 {
			return Bytes{}, errors.New("block size could not be found")
		}
	}
	if bs != 16 {
		return Bytes{}, fmt.Errorf("expecting block size of 16, found size of %d", bs)
	}

	// Find if encryption is ECB
	isECB, err := EncryptionOracle(encryptWithPrefix)
	if err != nil {
		return Bytes{}, err
	}
	if !isECB {
		return Bytes{}, errors.New("ECB encryption not detected")
	}

	// Find suffix string
	var targetPlaintext Bytes

	for targetByte := 0; targetByte < noPrefixLength-paddingLength; targetByte++ {
		for i := 0; i < 256; i++ {
			var prefixA, prefixB Bytes
			if targetByte < bs {
				prefixA = append(As(bs-targetByte-1), targetPlaintext...)
			} else {
				prefixA = targetPlaintext[targetByte-bs+1 : targetByte]
			}
			prefixA = append(prefixA, byte(i))

			prefixBLength := bs - (targetByte % bs) - 1
			prefixB = As(prefixBLength)

			prefix := append(prefixA, prefixB...)

			cipher, err := encryptWithPrefix(prefix)
			if err != nil {
				return Bytes{}, err
			}

			cipherPrefixBlock := cipher[:bs]

			targetBlockIndex := targetByte / bs
			targetBlockStart := (targetBlockIndex + 1) * bs
			targetBlockEnd := (targetBlockIndex + 2) * bs
			cipherTargetBlock := cipher[targetBlockStart:targetBlockEnd]

			if string(cipherPrefixBlock) == string(cipherTargetBlock) {
				targetPlaintext = append(targetPlaintext, byte(i))
				break
			}
			if i == 255 {
				fmt.Printf("%#v\n", string(targetPlaintext))
				fmt.Println(targetByte)
				fmt.Println(noPrefixLength)
				return Bytes{}, errors.New("could not find byte")
			}
		}
	}

	return targetPlaintext, nil
}
