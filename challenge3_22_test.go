package crp_test

import (
	"log"
	"testing"
	"time"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestFindMT19937SeedFromFirstOutput(t *testing.T) {
	expSeed := uint32(time.Now().Unix())
	mt := crp.NewMT19937(expSeed)

	seed := crp.FindMT19937SeedFromFirstOutput(mt.ExtractUint32())
	require.Equal(t, expSeed, seed)

	log.Println("Challenge 3.22 seed:", seed)
}
