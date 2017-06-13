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
	// Generate random prefix and suffix
	prefixLength := mrand.Intn(5)
	suffixLength := mrand.Intn(5)

	keySize := 16
	rdm, err := GenerateRandomBytes((keySize * 2) + prefixLength + suffixLength)
	if err != nil {
		return nil, err
	}
	key := rdm[0:keySize]
	iv := rdm[keySize : keySize*2]
	prefix := rdm[keySize*2 : keySize*2+prefixLength]
	suffix := rdm[keySize*2+prefixLength : keySize*2+prefixLength+suffixLength]
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	alteredMsg := make([]byte, 0, len(msg)+suffixLength+prefixLength)
	alteredMsg = append(alteredMsg, prefix...)
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

func findECBBlockSize(msg []byte, c cipher.Block) (int, error) {
	b := []byte("A")[0]
	maxBlockSize := 256
	prefix := make([]byte, 0, maxBlockSize)
	for i := 0; i < maxBlockSize; i++ {
		prefix = append(prefix, b)
		//fmt.Printf("len(prefix = %d; prefix = \"%s\"\n", len(prefix), prefix)
		contructedPlainmsg := make([]byte, 0, len(prefix)+len(msg))
		// Add prefix 2 times to build up my first 2 blocks at the same time
		contructedPlainmsg = append(contructedPlainmsg, prefix...)
		contructedPlainmsg = append(contructedPlainmsg, prefix...)
		contructedPlainmsg = append(contructedPlainmsg, msg...)
		encryptedMsg := ECBEncrypter(contructedPlainmsg, c)
		firstBlock := encryptedMsg[0:len(prefix)]
		secondBlock := encryptedMsg[len(prefix) : 2*len(prefix)]
		if bytes.Equal(firstBlock, secondBlock) {
			return len(prefix), nil
		}
	}
	return 0, fmt.Errorf("Reach ECB block max block size (%d)", maxBlockSize)
}

func isECBEncrypted(msg []byte, c cipher.Block) (bool, error) {
	if len(msg) < c.BlockSize()*3 {
		return false, fmt.Errorf("Error: len of msg need to be at least 2 times the block size (%d)", c.BlockSize()*3)
	}

	randomPrefix, err := GenerateRandomBytes(c.BlockSize() - mrand.Intn(5))
	if err != nil {
		return false, err
	}
	encryptedMsg := make([]byte, 0, len(randomPrefix)+len(msg))
	if bytes.Equal(encryptedMsg[c.BlockSize():c.BlockSize()*2], encryptedMsg[c.BlockSize()*2:c.BlockSize()*3]) {
		return true, nil
	}
	return false, nil
}

func oracleAesECB(msg, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	msg, err = Pkcs7Padding(msg, c.BlockSize())
	if err != nil {
		return nil, err
	}

	return ECBEncrypter(msg, c), nil
}

func buildRainbow(prefix, guessed, key, plainMsg []byte) (map[string][]byte, error) {
	rainbow := make(map[string][]byte)
	for i := 0; i < 256; i++ {
		msg := make([]byte, 0, len(prefix)+len(guessed)+len(plainMsg)+1)
		msg = append(msg, prefix...)
		msg = append(msg, guessed...)
		msg = append(msg, byte(i))
		msg = append(msg, plainMsg...)
		encryptedMsg, err := oracleAesECB(msg, key)
		if err != nil {
			return nil, err
		}

		rainbow[fmt.Sprintf("%s", encryptedMsg[0:len(key)])] = msg[len(key)-1 : len(key)]
	}

	return rainbow, nil
}
