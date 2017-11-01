package crp

func (b Bytes) CountRepeatedBlocks() map[int]int {
	repeatedBlocks := make(map[int]int)

	for bs := 2; bs <= len(b)/2; bs++ {
		if len(b)%bs != 0 {
			continue
		}

		seenBlocks := make(map[string]struct{})

		for i := bs; i <= len(b); i += bs {
			block1 := b[i-bs : i]
			if _, ok := seenBlocks[string(block1)]; ok {
				continue
			}
			seenBlocks[string(block1)] = struct{}{}

			for j := i + bs; j <= len(b); j += bs {
				block2 := b[j-bs : j]

				if string(block1) == string(block2) {
					repeatedBlocks[bs]++
				}
			}
		}
	}

	return repeatedBlocks
}
