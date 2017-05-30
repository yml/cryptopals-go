package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

var (
	englishFreqs = map[rune]float32{
		'a': 0.0651738,
		'b': 0.0124248,
		'c': 0.0217339,
		'd': 0.0349835,
		'e': 0.1041442,
		'f': 0.0197881,
		'g': 0.0158610,
		'h': 0.0492888,
		'i': 0.0558094,
		'j': 0.0009033,
		'k': 0.0050529,
		'l': 0.0331490,
		'm': 0.0202124,
		'n': 0.0564513,
		'o': 0.0596302,
		'p': 0.0137645,
		'q': 0.0008606,
		'r': 0.0497563,
		's': 0.0515760,
		't': 0.0729357,
		'u': 0.0225134,
		'v': 0.0082903,
		'w': 0.0171272,
		'x': 0.0013692,
		'y': 0.0145984,
		'z': 0.0007836,
		' ': 0.1918182,
	}
)

// HexToBase64 converts a byte slice from hex to base64
func HexToBase64(src []byte) ([]byte, error) {
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	dst2 := make([]byte, base64.StdEncoding.EncodedLen(len(dst)))
	base64.StdEncoding.Encode(dst2, dst)
	return dst2, nil

}

func XORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	return n
}

func SingleByteXOR(dst, a []byte, b byte) {
	for i := 0; i < len(a); i++ {
		dst[i] = a[i] ^ b
	}
	return
}

func scoreEnglishText(s string) float32 {
	var score float32
	for _, r := range s {
		score += englishFreqs[r]
	}
	return score
}

func main() {
	fmt.Println("vim-go")
}
