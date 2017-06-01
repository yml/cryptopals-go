package main

import (
	"bytes"
	"fmt"
)

// PaddingPkcs7 return the slice with the appropriate padding
func PaddingPkcs7(src []byte, blockSize int) ([]byte, error) {
	n := len(src)
	if n > blockSize {
		return nil, fmt.Errorf("The len(src)=%d must be smaller than len(blockSize)=%d", n, blockSize)
	} else if blockSize < 1 {
		return nil, fmt.Errorf("blockSize must be more than 1")
	} else if blockSize > 255 {
		return nil, fmt.Errorf("blockSize must be less than 255")
	}
	npad := blockSize - n
	dst := make([]byte, n, blockSize)
	copy(dst, src)
	dst = append(dst, bytes.Repeat([]byte{byte(npad)}, npad)...)
	return dst, nil
}
