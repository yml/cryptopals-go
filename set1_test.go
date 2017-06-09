package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"testing"
)

func Test_Challenge1_HextoBase64(t *testing.T) {
	cases := []struct {
		input, expected []byte
	}{
		{
			input:    []byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"),
			expected: []byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"),
		},
	}

	for _, c := range cases {
		got, err := HexToBase64(c.input)
		if err != nil {
			t.Fatalf("An error occured : %v\n", err)
		}
		fmt.Printf("got = %s\n", got)
		fmt.Printf("expected = %s\n", c.expected)
		if bytes.Compare(got, c.expected) != 0 {
			t.Fatalf("got = %s\nexpected = %s\n", got, c.expected)
		}
	}
}

func Test_Challenge2_FixedXOR(t *testing.T) {
	challenge := struct {
		input1HexEncoded, input2HexEncoded, expectedHexEncoded []byte
	}{
		input1HexEncoded:   []byte("1c0111001f010100061a024b53535009181c"),
		input2HexEncoded:   []byte("686974207468652062756c6c277320657965"),
		expectedHexEncoded: []byte("746865206b696420646f6e277420706c6179"),
	}

	// Hex decode input1
	input1 := make([]byte, hex.DecodedLen(len(challenge.input1HexEncoded)))
	_, err := hex.Decode(input1, challenge.input1HexEncoded)
	if err != nil {
		t.Fatalf("could not hex.decode, %s (%v)", challenge.input1HexEncoded, err)
	}

	// Hex decode input2
	input2 := make([]byte, hex.DecodedLen(len(challenge.input2HexEncoded)))
	_, err = hex.Decode(input2, challenge.input2HexEncoded)
	if err != nil {
		t.Fatalf("could not hex.decode, %s (%v)", challenge.input2HexEncoded, err)
	}

	// XOR input1 and input2
	dst := make([]byte, len(input2))
	_ = XORBytes(dst, input1, input2)

	// Hex decode expected result
	expected := make([]byte, hex.DecodedLen(len(challenge.expectedHexEncoded)))
	_, err = hex.Decode(expected, challenge.expectedHexEncoded)
	if err != nil {
		t.Fatalf("could not hex.decode, %s (%v)", challenge.expectedHexEncoded, err)
	}
	fmt.Printf("expected\n  %b\n", expected)
	fmt.Printf("dst\n  %b\n", dst)

	// compare expected result and the result we got
	if bytes.Compare(dst, expected) != 0 {
		t.Fatalf("got = %s\n expected = %s\n", dst, expected)
	}
}

func Test_Challenge3_SingleByteXORCipher(t *testing.T) {
	challenge := struct {
		inputHexEncoded []byte
	}{
		inputHexEncoded: []byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"),
	}
	input := make([]byte, hex.DecodedLen(len(challenge.inputHexEncoded)))
	_, err := hex.Decode(input, challenge.inputHexEncoded)
	if err != nil {
		t.Fatalf("Could not hex.decode, %s (%v)\n", challenge.inputHexEncoded, err)
	}

	decodedMsg, byteCipher, _ := breakSingleByteXOR(input, scoreEnglishText)
	fmt.Printf("byte cipher = %v ; msg = %s\n", byteCipher, decodedMsg)
}

func Test_Challenge4_DetectSingleCharacterXOR(t *testing.T) {
	f, err := os.Open("data/challenge-data-4.txt")
	if err != nil {
		t.Fatal("Could not read the challenge data")
	}
	defer f.Close()

	maxScore := float32(0)
	var guessedMsgByteCipher byte
	var guessedMsg []byte

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		input := make([]byte, hex.DecodedLen(len(scanner.Bytes())))
		_, err := hex.Decode(input, scanner.Bytes())
		if err != nil {
			t.Fatalf("could not decode, %s (%v)\n", scanner.Text(), err)
		}
		decodedMsg, byteCipher, score := breakSingleByteXOR(input, scoreEnglishText)
		if score > maxScore {
			maxScore = score
			guessedMsg = make([]byte, len(decodedMsg))
			copy(guessedMsg, decodedMsg)
			guessedMsgByteCipher = byteCipher
		}
	}
	fmt.Printf("byte cipher = %v ; msg = %s\n", guessedMsgByteCipher, guessedMsg)
}

func Test_Challenge5_ImplementRepeatingKeyXOR(t *testing.T) {
	challenges := struct {
		input, expectedHexEncoded []byte
	}{
		input: []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`),
		expectedHexEncoded: []byte(`0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`),
	}
	key := []byte("ICE")
	expected := make([]byte, hex.DecodedLen(len(challenges.expectedHexEncoded)))
	_, err := hex.Decode(expected, challenges.expectedHexEncoded)
	if err != nil {
		t.Fatalf("could not decode, %v", err)
	}

	dst := make([]byte, len(challenges.input))
	applyXORWithRepeatKey(dst, challenges.input, key)
	fmt.Printf("got =\n  %s\n", dst)
	fmt.Printf("expected =\n  %s\n", expected)
	if bytes.Compare(dst, expected) != 0 {
		t.Fatalf("got =\n  %s\nexpected =\n  %s\n", dst, expected)
	}

}

func Test_Challenge6_BreakRepeatingKeyXOR(t *testing.T) {
	t.Run("Test Hamming Distance", func(t *testing.T) {
		expected := 37
		got, err := hammingDistance(
			[]byte("this is a test"),
			[]byte("wokka wokka!!!"),
		)
		if err != nil {
			t.Fatal("An error occured while calculating hamming distance", err)
		}
		if got != expected {
			t.Fatalf("got = %d ; expected = %d", got, expected)
		}
	})
	t.Run("Find key Size", func(t *testing.T) {
		maxkeysize := 40
		EncryptedMsg, err := base64DecodeFile("data/challenge-data-6.txt")
		if err != nil {
			t.Fatal("Could not read or base64 decode", err)
		}

		// find the keysize
		keySize, err := findKeySize(EncryptedMsg, maxkeysize, hammingDistance)
		if err != nil {
			t.Fatal("could not find the keysize", err)
		}
		fmt.Println("keysize =", keySize)

		// guess the key
		blocks := getTranposedBlocks(EncryptedMsg, keySize)
		fmt.Println("len(blocks) =", len(blocks))
		key := make([]byte, keySize)
		for i := range blocks {
			_, byteCipher, _ := breakSingleByteXOR(blocks[i], scoreEnglishText)
			key[i] = byteCipher
		}
		fmt.Printf("key =\n%s\n", key)
		decodedMsg := make([]byte, len(EncryptedMsg))
		applyXORWithRepeatKey(decodedMsg, EncryptedMsg, key)
		fmt.Printf("decoded data =\n%s\n\n\n", decodedMsg)
	})
}

func Test_Challenge7_DecryptAESInECBMode(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	encryptedMsg, err := base64DecodeFile("data/challenge-data-7.txt")
	if err != nil {
		t.Fatal("Could not read or base64 decode", err)
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("could not create the aes cipher")
	}

	decryptedMsg := ECBDecrypter(encryptedMsg, aesCipher)
	fmt.Printf("key = %s\n", key)
	fmt.Printf("Decoded mesage = \n%s\n\n", decryptedMsg)
}

func Test_Challenge8_DetectAESInECBMode(t *testing.T) {
	f, err := os.Open("data/challenge-data-8.txt")
	if err != nil {
		t.Fatal("Could not read file", err)
	}
	defer f.Close()

	guessedLine := 0
	minAverage := float64(100000000)
	l := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		cipherText := make([]byte, hex.DecodedLen(len(scanner.Bytes())))
		_, err := hex.Decode(cipherText, scanner.Bytes())
		if err != nil {
			t.Fatal("Could not hex decode the line", err)
		}
		blockSize := 16
		numberOfBlocks := int(math.Ceil(float64(len(cipherText)) / float64(blockSize)))
		blocks := getBlocks(cipherText, blockSize, numberOfBlocks)
		if err != nil {
			t.Fatal("Could not split the cipherText in blocks", err)
		}
		avg, err := averageDistanceBlocks(blocks, hammingDistance)
		if avg < minAverage {
			minAverage = avg
			guessedLine = l
		}
		l++
	}
	fmt.Println("guessed line (0 based) = ", guessedLine)
}
