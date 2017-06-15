package main

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
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

// XORBytes XOR 2  []bytes and returns the length of the result
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

// SingleByteXOR XOR a []byte against a single byte
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

// breakSingleByteXOR returns te decodedMsg and the guessed byte cypher.
func breakSingleByteXOR(msg []byte, scoringFn func(s string) float32) ([]byte, byte, float32) {
	var (
		byteCipher byte
		maxScore   float32
	)
	dst := make([]byte, len(msg))
	decodedMsg := make([]byte, len(msg))

	for i := 0; i < 255; i++ {
		b := byte(i)
		SingleByteXOR(dst, msg, b)
		msg := string(dst[:])
		score := scoreEnglishText(msg)
		if score > maxScore {
			maxScore = score
			copy(decodedMsg, dst)
			byteCipher = b
		}
	}
	return decodedMsg, byteCipher, maxScore

}

func applyXORWithRepeatKey(dst, msg, key []byte) {
	for i := range msg {
		if msg[i] != 0 {
			dst[i] = msg[i] ^ key[i%len(key)]
		}
	}
}

func base64DecodeFile(fname string) ([]byte, error) {
	encryptedFileBytes, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	EncryptedMsg := make([]byte, base64.StdEncoding.DecodedLen(len(encryptedFileBytes)))
	_, err = base64.StdEncoding.Decode(EncryptedMsg, encryptedFileBytes)
	return EncryptedMsg, err

}

func hammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, fmt.Errorf("Undefined for non equal length")
	}
	d := 0
	for i := 0; i < len(a); i++ {
		b := a[i] ^ b[i]
		for b != 0 {
			b &= b - 1
			d++
		}
	}
	return d, nil
}

// getBlocks returns a slice of `n` []byte of len `size` from the `msg`
func getBlocks(msg []byte, size, n int) [][]byte {
	blocks := make([][]byte, n)
	for i := 0; i < n; i++ {
		blocks[i] = make([]byte, size)
		copy(blocks[i], msg[i*size:(i+1)*size])
	}
	return blocks
}

// getTranposedBlocks returns [][]byte composed tranposed blocks of keysize
func getTranposedBlocks(msg []byte, size int) [][]byte {
	blocks := make([][]byte, int(math.Ceil(float64(len(msg))/float64(size))))
	for i := 0; i < len(blocks); i++ {
		blocks[i] = make([]byte, size)
		upTo := (i + 1) * size
		if len(msg) < upTo {
			upTo = len(msg)
		}
		copy(blocks[i], msg[i*size:upTo])
	}
	transposedBlocks := make([][]byte, size)
	for i := 0; i < len(transposedBlocks); i++ {
		transposedBlocks[i] = make([]byte, len(blocks))
		for j := 0; j < len(blocks); j++ {
			transposedBlocks[i][j] = blocks[j][i]
		}
	}
	return transposedBlocks
}

// averageDistanceBlocks returns the normalize average disance between blocks
func averageDistanceBlocks(blocks [][]byte, distanceFn func(a, b []byte) (int, error)) (float64, error) {
	iteration := float64(0)
	// all blocks have the same keysize
	keySize := float64(len(blocks[0]))
	average := float64(0)
	for i := range blocks {
		for j := 0; j < len(blocks); j++ {
			if i != j {
				d, err := distanceFn(blocks[i], blocks[j])
				if err != nil {
					return 0, err
				}
				average += float64(d) / keySize
				iteration++
			}
		}
	}
	average = average / iteration
	return average, nil
}

// findKeySize returns the guess size of the key
func findKeySize(msg []byte, maxKeySize int, distanceFn func(a, b []byte) (int, error)) (int, error) {
	numberOfBlocks := 4
	// big number that should be replace on first iteration
	minAverage := float64(1000000)
	keysize := 0
	for i := 2; i < maxKeySize; i++ {
		blocks := getBlocks(msg, i, numberOfBlocks)
		avg, err := averageDistanceBlocks(blocks, distanceFn)
		if err != nil {
			return 0, err
		}
		if minAverage > avg {
			minAverage = avg
			keysize = i
		}

	}
	return keysize, nil

}

// ECBDecrypter returns the decrypted message using ECB mode.
func ECBDecrypter(msg []byte, c cipher.Block) []byte {
	decryptedMsg := make([]byte, 0, len(msg))
	var decryptedBlock []byte
	blockSize := c.BlockSize()
	for i := 0; i < len(msg)/blockSize; i++ {
		decryptedBlock = decryptedMsg[i*blockSize : (i+1)*blockSize]
		c.Decrypt(decryptedBlock, msg[i*blockSize:(i+1)*blockSize])
		decryptedMsg = append(decryptedMsg, decryptedBlock...)
	}
	return decryptedMsg
}

// ECBEncrypter returns the encrypted msg using ECB mode.
func ECBEncrypter(msg []byte, c cipher.Block) []byte {
	encryptedMsg := make([]byte, 0, len(msg))
	blockSize := c.BlockSize()
	encryptedBlock := make([]byte, blockSize)
	for i := 0; i < len(msg)/blockSize; i++ {
		encryptedBlock = encryptedMsg[i*blockSize : (i+1)*blockSize]
		c.Encrypt(encryptedBlock, msg[i*blockSize:(i+1)*blockSize])
		encryptedMsg = append(encryptedMsg, encryptedBlock...)
		encryptedBlock = encryptedBlock[0:0]
	}
	return encryptedMsg
}
