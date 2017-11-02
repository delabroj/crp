package crp_test

import (
	"log"
	"testing"

	"github.com/delabroj/crp"
)

func TestMT19937(t *testing.T) {
	mt := crp.NewMT19937(1)

	var ints []uint32
	for i := 0; i < 4; i++ {
		ints = append(ints, mt.ExtractUint32())
	}
	log.Println("Challenge 3.21 random ints:", ints)
}
