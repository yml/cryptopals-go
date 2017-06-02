package main

import (
	"bytes"
	"fmt"
)

// PaddingPkcs7 return the slice with the appropriate padding
func PaddingPkcs7(src []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 {
		return nil, fmt.Errorf("blockSize must be more than 1")
	} else if blockSize > 255 {
		return nil, fmt.Errorf("blockSize must be less than 255")
	}

	npad := blockSize - len(src)%blockSize
	if npad < blockSize {
		src = append(src, bytes.Repeat([]byte{byte(npad)}, npad)...)
	}
	return src, nil
}
