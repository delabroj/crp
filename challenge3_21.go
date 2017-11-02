package crp

type MT19937 struct {
	mt    [624]uint32
	index int
}

func NewMT19937(seed uint32) MT19937 {
	m := MT19937{}
	m.mt[0] = seed
	for i := 1; i < 624; i++ {
		m.mt[i] = 1812433253*(m.mt[i-1]^m.mt[i-1]>>30) + uint32(i)
	}

	return m
}

func (m *MT19937) Twist() {
	for i := 0; i < 624; i++ {
		y := (m.mt[i] & 0x80000000) + (m.mt[(i+1)%624] & 0x7fffffff)
		m.mt[i] = m.mt[(i+397)%624] ^ y>>1

		if y%2 != 0 {
			m.mt[i] = m.mt[i] ^ 0x9908b0df
		}
	}
	m.index = 0
}

func (m *MT19937) ExtractUint32() uint32 {
	if m.index >= 624 {
		m.Twist()
	}

	y := m.mt[m.index]

	y ^= y >> 11
	y ^= y << 7 & 2636928640
	y ^= y << 15 & 4022730752
	y ^= y >> 18

	m.index++

	return y
}
