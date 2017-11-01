package crp

import (
	"errors"
	"fmt"
	"strconv"
)

func HexXOR(a, b Hex) (Hex, error) {
	if len(a) != len(b) {
		return Hex{}, errors.New("inputs must be of equal length")
	}

	if len(a)%2 != 0 {
		return Hex{}, errors.New("inputs must have an even number of digits")
	}

	var ret Hex

	for i := 0; i < len(a)/2; i++ {
		var aInt, bInt int64
		var err error
		if aInt, err = strconv.ParseInt(string(a[2*i:2*(i+1)]), 16, 32); err != nil {
			return Hex{}, err
		}
		if bInt, err = strconv.ParseInt(string(b[2*i:2*(i+1)]), 16, 32); err != nil {
			return Hex{}, err
		}
		retInt := byte(aInt) ^ byte(bInt)
		ret = append(ret, Hex(fmt.Sprintf("%.2x", retInt))...)
	}

	return ret, nil
}
