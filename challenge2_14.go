package crp

import (
	"errors"
	"fmt"
	"strings"
)

func FindLengthOfECBPrefix(encryptWithRoot func(Bytes) (Bytes, error)) (int, error) {
	var prefixLength int

	bs := 16

	results := make(map[int]int)

	// Try 4 times with different root character to avoid cases where last character
	// of padding or first character of suffix matches root character
	for try := 0; try < 4; try++ {
		root := Bytes(strings.Repeat(string(byte(try)), 3*bs))

		var firstFound bool
		var prevCipher Bytes
		var blockOfFirstDifference int
		var prevBlockOfFirstDifference int
		for i := 0; i <= 2*bs; i++ {
			cipher, err := encryptWithRoot(root[:i])
			if err != nil {
				return 0, err
			}

			for i := 0; i < len(prevCipher); i++ {
				if cipher[i] != prevCipher[i] {
					blockOfFirstDifference = i / bs
					break
				}
				blockOfFirstDifference = len(prevCipher) / bs
			}
			if blockOfFirstDifference != prevBlockOfFirstDifference && len(prevCipher) > 0 {
				if firstFound {
					prefixLength = bs*(blockOfFirstDifference) - i + 1
					break
				}
				firstFound = true
			}
			prevBlockOfFirstDifference = blockOfFirstDifference

			prevCipher = make(Bytes, len(cipher))
			copy(prevCipher, cipher)
		}

		results[prefixLength]++
	}

	var maxCount int
	for k, v := range results {
		if v > maxCount {
			maxCount = v
			prefixLength = k
		}
	}

	return prefixLength, nil
}

func BreakECBViaCustomRoot(encryptWithRoot func(Bytes) (Bytes, error)) (Bytes, error) {
	As := func(n int) Bytes {
		return Bytes(strings.Repeat("A", n))
	}

	// Find block size and padding length
	var bs int
	var paddingLength int

	cipher, err := encryptWithRoot(Bytes{})
	if err != nil {
		return Bytes{}, err
	}
	noRootLength := len(cipher)

	for i := 1; i <= 16; i++ {
		root := As(i)
		cipher, err := encryptWithRoot(root)
		if err != nil {
			return Bytes{}, err
		}
		if len(cipher) != noRootLength {
			bs = len(cipher) - noRootLength
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
	isECB, err := EncryptionOracle(encryptWithRoot)
	if err != nil {
		return Bytes{}, err
	}
	if !isECB {
		return Bytes{}, errors.New("ECB encryption not detected")
	}

	// Find prefix length
	prefixLength, err := FindLengthOfECBPrefix(encryptWithRoot)
	if err != nil {
		return Bytes{}, err
	}

	// Find suffix string
	var targetPlaintext Bytes

	prefixPadding := As(bs - prefixLength%bs)
	for targetByte := 0; targetByte < noRootLength-prefixLength-paddingLength; targetByte++ {
		for i := 0; i < 256; i++ {
			var rootA, rootB Bytes
			if targetByte < bs {
				rootA = append(As(bs-targetByte-1), targetPlaintext...)
			} else {
				rootA = targetPlaintext[targetByte-bs+1 : targetByte]
			}
			rootA = append(rootA, byte(i))

			prefixBLength := bs - (targetByte % bs) - 1
			rootB = As(prefixBLength)

			root := append(rootA, rootB...)
			root = append(prefixPadding, root...)

			cipher, err := encryptWithRoot(root)
			if err != nil {
				return Bytes{}, err
			}

			prefixBlockCount := (prefixLength + len(prefixPadding)) / bs
			cipherRootBlock := cipher[prefixBlockCount*bs : (prefixBlockCount+1)*bs]

			targetBlockIndex := prefixBlockCount + targetByte/bs
			targetBlockStart := (targetBlockIndex + 1) * bs
			targetBlockEnd := (targetBlockIndex + 2) * bs
			cipherTargetBlock := cipher[targetBlockStart:targetBlockEnd]

			if string(cipherRootBlock) == string(cipherTargetBlock) {
				targetPlaintext = append(targetPlaintext, byte(i))
				// fmt.Printf("%#v\n", string(targetPlaintext))
				break
			}
			if i == 255 {
				fmt.Printf("%#v\n", string(targetPlaintext))
				return Bytes{}, errors.New("could not find byte")
			}
		}
	}

	return targetPlaintext, nil
}
