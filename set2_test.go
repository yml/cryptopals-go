package main

import (
	"bytes"
	"testing"
)

func Test_challenge9_ImplementPKCS7Padding(t *testing.T) {
	challenge := struct {
		input, expectedPaddedOut []byte
		blockSize                int
	}{
		input:             []byte("YELLOW SUBMARINE"),
		expectedPaddedOut: []byte("YELLOW SUBMARINE\x04\x04\x04\x04"),
		blockSize:         20,
	}

	got, err := PaddingPkcs7(challenge.input, challenge.blockSize)
	if err != nil {
		t.Fatal("An error occured while pkcs8 padding src ", err)
	}
	if bytes.Compare(got, challenge.expectedPaddedOut) != 0 {
		t.Fatalf("got =\n%s\n ; expected =\n%s\n", got, challenge.expectedPaddedOut)
	}
}
