package crp

import "math"

func FindMT19937SeedFromFirstOutput(out uint32) uint32 {
	var seed uint32
	for seed = uint32(0); seed < math.MaxUint32; seed++ {
		y := seed ^ seed>>11
		y ^= y << 7 & 2636928640
		y ^= y << 15 & 4022730752
		y ^= y >> 18

		if y == out {
			break
		}
	}
	return seed
}
