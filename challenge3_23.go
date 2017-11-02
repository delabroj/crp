package crp

func MT19937Temper(n uint32) uint32 {
	y := n
	y ^= y >> 11
	y ^= y << 7 & 2636928640
	y ^= y << 15 & 4022730752
	y ^= y >> 18

	return y
}

func MT19937Untemper(n uint32) uint32 {
	y := n
	y ^= y >> 18

	y ^= y << 15 & 4022730752

	a := y ^ y<<7&2636928640
	a = y ^ a<<7&2636928640
	a = y ^ a<<7&2636928640
	a = y ^ a<<7&2636928640
	y ^= a << 7 & 2636928640

	a = y ^ y>>11
	y ^= a >> 11

	return y
}

func CloneMT19937Generator(record [624]uint32) MT19937 {
	m := MT19937{}

	for i := range m.mt {
		m.mt[i] = MT19937Untemper(record[i])
	}
	m.Twist()

	return m
}
