package crp_test

import (
	"testing"
	"time"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestMT19937TemperUntemper(t *testing.T) {
	mt := crp.NewMT19937(1)
	for i := 0; i < 10000; i++ {
		expSeed := mt.ExtractUint32()
		seed := crp.MT19937Untemper(crp.MT19937Temper(expSeed))
		require.Equal(t, expSeed, seed)
	}
}

func TestCloneMT19937Generator(t *testing.T) {
	mt := crp.NewMT19937(uint32(time.Now().UnixNano()))
	for i := 0; i < 1000; i++ {
		mt.ExtractUint32()
	}

	var record [624]uint32
	for i := range record {
		record[i] = mt.ExtractUint32()
	}
	mtClone := crp.CloneMT19937Generator(record)
	for i := 0; i < 624; i++ {
		require.Equal(t, mt.ExtractUint32(), mtClone.ExtractUint32())
	}
}
