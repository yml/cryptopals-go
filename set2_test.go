package main

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"testing"
)

func Test_Challenge9_ImplementPKCS7Padding(t *testing.T) {
	challenge := struct {
		input, expectedPaddedOut []byte
		blockSize                int
	}{
		input:             []byte("YELLOW SUBMARINE"),
		expectedPaddedOut: []byte("YELLOW SUBMARINE\x04\x04\x04\x04"),
		blockSize:         20,
	}

	got, err := Pkcs7Padding(challenge.input, challenge.blockSize)
	if err != nil {
		t.Fatal("An error occured while pkcs8 padding src ", err)
	}
	if bytes.Compare(got, challenge.expectedPaddedOut) != 0 {
		t.Fatalf("got =\n%s\n ; expected =\n%s\n", got, challenge.expectedPaddedOut)
	}
}

func Test_Challenge10_ImplementCBCMode(t *testing.T) {
	challenge := struct {
		key, IV []byte
	}{
		key: []byte("YELLOW SUBMARINE"),
		IV:  []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	}
	msg, err := base64DecodeFile("data/challenge-data-10.txt")
	if err != nil {
		t.Fatal("Could base64 decode the file", err)
	}
	cipher, err := aes.NewCipher(challenge.key)
	if err != nil {
		t.Fatal("Could not create an aes cipher", err)
	}

	numberOfBlock := len(msg) / len(challenge.key)
	fmt.Println("numberOfBlock", numberOfBlock)
	npad := len(msg) % len(challenge.key)
	if npad != 0 {
		t.Fatal("Encrypted msg must be a factor of len(key)")
	}

	// decrypt
	decryptedMsg := CBCDecrypter(msg, challenge.IV, cipher)

	fmt.Printf("len(key) = %d ; len(IV) = %d ; len(msg) = %d\n", len(challenge.key), len(challenge.IV), len(msg))
	fmt.Printf("%q\n", decryptedMsg)

	// encrypt
	encryptedMsg := CBCEncrypter(decryptedMsg, challenge.IV, cipher)
	// Check equality with the original
	if bytes.Compare(encryptedMsg, msg) != 0 {
		t.Fatalf("got = \n%q\nexpected = \n%q\n", encryptedMsg, msg)
	}
}

func Test_Challenge11_EBC_CBC_DetectionOracle(t *testing.T) {
	t.Run("Generate Random key", func(t *testing.T) {
		keySize := 16
		key, err := GenerateRandomBytes(keySize)
		if err != nil {
			t.Fatal(err)
		}
		if len(key) != keySize {
			t.Fatal("Generated key does not the right key size got = ", len(key), " expected = ", keySize)
		}
		k2, err := GenerateRandomBytes(keySize)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(key, k2) == true {
			t.Fatal("key are not random keys 1 =", key, " key2 =", k2)
		}
	})
	t.Run("Encryption Oracle", func(t *testing.T) {
		msg := make([]byte, 48)
		encryptedMsg, err := encryptionOracle(msg)
		if err != nil {
			t.Fatal(err)
		}

		// All the bytes in msg are identical compare 2 consequitive blocks and checks for equality. If equal they have been ecrypted with ECB.
		if bytes.Equal(encryptedMsg[16:32], encryptedMsg[32:48]) {
			fmt.Println("Guessed encryption mode: ECB")
		} else {
			fmt.Println("Guessed encryption mode: CBC")
		}
	})
}
