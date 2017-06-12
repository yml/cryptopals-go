package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"time"
)

// Pkcs7Padding return the slice with the appropriate padding
func Pkcs7Padding(src []byte, blockSize int) ([]byte, error) {
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

//CBCDecrypter returns the decrypted message using the CBC mode
func CBCDecrypter(msg, iv []byte, c cipher.Block) []byte {
	decryptedMsg := make([]byte, 0, len(msg))
	var decryptedBlock []byte
	blockSize := c.BlockSize()

	for i := 0; i < len(msg)/blockSize; i++ {
		decryptedBlock = decryptedMsg[i*blockSize : (i+1)*blockSize]
		c.Decrypt(decryptedBlock, msg[i*blockSize:(i+1)*blockSize])
		for j := 0; j < blockSize; j++ {
			if i == 0 {
				decryptedBlock[j] = iv[j] ^ decryptedBlock[j]
			} else {
				decryptedBlock[j] = msg[(i-1)*blockSize : i*blockSize][j] ^ decryptedBlock[j]
			}
		}
		decryptedMsg = append(decryptedMsg, decryptedBlock...)
	}
	return decryptedMsg
}

// CBCEncrypter returns an encrypted msg using the CBC mode
func CBCEncrypter(msg, iv []byte, c cipher.Block) []byte {
	encryptedMsg := make([]byte, len(msg))
	blockSize := c.BlockSize()
	encryptedBlock := make([]byte, blockSize)

	for i := 0; i < len(msg)/blockSize; i++ {
		for j := 0; j < blockSize; j++ {
			if i == 0 {
				encryptedBlock[j] = iv[j] ^ msg[i*blockSize : (i+1)*blockSize][j]
			} else {
				encryptedBlock[j] = encryptedMsg[(i-1)*blockSize : i*blockSize][j] ^ msg[i*blockSize : (i+1)*blockSize][j]
			}
			c.Encrypt(encryptedMsg[i*blockSize:(i+1)*blockSize], encryptedBlock)
		}
	}
	return encryptedMsg
}

// GenerateRandomBytes returns a random key of the specified size
func GenerateRandomBytes(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptionOracle(msg []byte) ([]byte, error) {
	mrand.Seed(time.Now().Unix())
	// Generate random preffix and suffix
	preffixCount := mrand.Intn(5)
	suffixCount := mrand.Intn(5)

	keySize := 16
	rdm, err := GenerateRandomBytes((keySize * 2) + preffixCount + suffixCount)
	if err != nil {
		return nil, err
	}
	key := rdm[0:keySize]
	iv := rdm[keySize : keySize*2]
	preffix := rdm[keySize*2 : keySize*2+preffixCount]
	suffix := rdm[keySize*2+preffixCount : keySize*2+preffixCount+suffixCount]
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	alteredMsg := make([]byte, 0, len(msg)+suffixCount+preffixCount)
	alteredMsg = append(alteredMsg, preffix...)
	alteredMsg = append(alteredMsg, msg...)
	alteredMsg = append(alteredMsg, suffix...)
	coin := mrand.Intn(2)
	fmt.Println("coin =", coin)
	var encryptedMsg []byte
	if coin == 0 {
		fmt.Println("CBC encryption")
		encryptedMsg = CBCEncrypter(alteredMsg, iv, c)
	} else {
		fmt.Println("ECB encryption")
		encryptedMsg = ECBEncrypter(alteredMsg, c)
	}
	return encryptedMsg, nil
}
