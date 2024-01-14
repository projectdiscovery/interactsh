package server

import (
	"bytes"
	"math/big"
)

var (
	base36 = []byte{
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
		'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
		'u', 'v', 'w', 'x', 'y', 'z',
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}

	bigRadix = big.NewInt(36)
	bigZero  = big.NewInt(0)
)

func base36Hash(s string) byte {
	i := 0
	for _, c := range s {
		i += int(c)
	}
	return base36[i%36]
}

func base36Encode(b []byte) string {
	x := new(big.Int)
	x.SetBytes(b)

	answer := make([]byte, 0, len(b)*136/100)
	for x.Cmp(bigZero) > 0 {
		mod := new(big.Int)
		x.DivMod(x, bigRadix, mod)
		answer = append(answer, base36[mod.Int64()])
	}

	for _, i := range b {
		if i != 0 {
			break
		}
		answer = append(answer, base36[0])
	}

	alen := len(answer)
	for i := 0; i < alen/2; i++ {
		answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
	}

	return string(answer)
}

func base36Add(b1, b2 string) string {
	return string(base36[(bytes.Index(base36, []byte(b1))+bytes.Index(base36, []byte(b2)))%36])
}

func base36Sub(b1, b2 string) string {
	return string(base36[(36+bytes.Index(base36, []byte(b1))-bytes.Index(base36, []byte(b2)))%36])
}

func base36XorEncode(iv, s string) string {
	b1 := []rune(iv)
	b2 := []rune(s)
	r := ""
	for b := 0; b < len(b2); b++ {
		i := b % 2
		c := base36Add(string(b2[b]), string(b1[i]))
		r += c
		b1[i] = []rune(c)[0]
	}
	return r
}
func base36XorDecode(iv, r string) string {
	b1 := []rune(iv)
	s := ""
	for i := 0; i < len(r); i++ {
		b := i % 2
		c := base36Sub(string(r[i]), string(b1[b]))
		s += c
		b1[b] = []rune(r)[i]
	}
	return s
}
