package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func Test_Chalenge1_HextoBase64(t *testing.T) {
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

func Test_Chalenge2_FixedXOR(t *testing.T) {
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

	result := struct {
		msg        string
		byteCipher byte
		score      float32
	}{}

	for i := 0; i < 255; i++ {
		b := byte(i)
		dst := make([]byte, len(input))
		SingleByteXOR(dst, input, b)
		msg := string(dst[:])
		score := scoreEnglishText(msg)
		if score > result.score {
			result.score = score
			result.msg = msg
			result.byteCipher = b
		}
	}
	fmt.Printf("byte cipher = %v ; msg = %s\n", result.byteCipher, result.msg)
}

func Test_Challenge4_DetectSingleCharacterXOR(t *testing.T) {
	f, err := os.Open("data/challenge-data-4.txt")
	if err != nil {
		t.Fatal("Could not read the challenge data")
	}
	type result struct {
		msg        string
		byteCipher byte
		score      float32
	}

	res := result{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		input := make([]byte, hex.DecodedLen(len(scanner.Bytes())))
		_, err := hex.Decode(input, scanner.Bytes())
		if err != nil {
			t.Fatalf("could not decode, %s (%v)\n", scanner.Text(), err)
		}
		for i := 0; i < 255; i++ {
			b := byte(i)
			dst := make([]byte, len(input))
			SingleByteXOR(dst, input, b)
			msg := string(dst[:])
			score := scoreEnglishText(msg)
			if score > res.score {
				res.score = score
				res.msg = msg
				res.byteCipher = b
			}
		}

	}
	fmt.Printf("byte cipher = %v ; msg = %s\n", res.byteCipher, res.msg)
}
