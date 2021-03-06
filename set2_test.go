package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/davecgh/go-spew/spew"
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

	got, err := Pkcs7Pad(challenge.input, challenge.blockSize)
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

		// All the bytes in msg are identical compare 2 consecutive blocks and checks for equality. If equal they have been encrypted with ECB.
		if bytes.Equal(encryptedMsg[16:32], encryptedMsg[32:48]) {
			fmt.Println("Guessed encryption mode: ECB")
		} else {
			fmt.Println("Guessed encryption mode: CBC")
		}
	})
}

func Test_Challenge12_ByteAtATimeECBDecryption(t *testing.T) {
	base64Msg := []byte("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
	key := []byte("YELLOW SUBMARINE")
	var guessedBlockSize int

	plainMsg := make([]byte, base64.StdEncoding.DecodedLen(len(base64Msg)))
	_, err := base64.StdEncoding.Decode(plainMsg, base64Msg)
	if err != nil {
		t.Fatal("Could not decode base64Msg", err)
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("Could not create the aes cipher block")
	}
	t.Run("Find ECB block size", func(t *testing.T) {
		blockSize, err := findECBBlockSize(plainMsg, c)
		if err != nil {
			t.Fatal("Could not find ECB block Size", err)
		}
		if len(key) != blockSize {
			t.Fatalf("Wrong block size expected = %d ; got = %d", len(key), blockSize)
		}
		fmt.Println("ECB block size =", blockSize)
		guessedBlockSize = blockSize
	})
	t.Run("Detect that we are using ECB", func(t *testing.T) {
		fmt.Println("guessedBlockSize =", guessedBlockSize)
		msg := make([]byte, 3*guessedBlockSize)
		ok, err := isECBEncrypted(msg, c)
		if err != nil {
			t.Fatal("An error occured while running isECBEncrypted ", err)
		}
		if !ok {
			t.Fatal("msg is encrypted using and aes cipher in ECB mode by construction")
		}
		fmt.Println("By construction we are using an aes cipher in ECB mode")

	})
	t.Run("findingLastBytes", func(t *testing.T) {
		// Build a rainbow map of all the possible value for the last byte
		paddedPlainMsg, err := Pkcs7Pad(plainMsg, guessedBlockSize)
		if err != nil {
			t.Fatal(err)
		}

		prefix := bytes.Repeat([]byte("A"), guessedBlockSize)
		guessedMsg := make([]byte, 0, len(paddedPlainMsg))
		guessed := make([]byte, 0, guessedBlockSize)
		fmt.Println("len(prefix) =", len(prefix))
		fmt.Println("len(paddedPlainMsg) =", len(paddedPlainMsg))
		for j := 0; j < len(paddedPlainMsg); j += guessedBlockSize {
			guessed = guessed[0:0]
			for i := 1; i < guessedBlockSize+1; i++ {
				rainbow, err := buildRainbow(prefix[0:guessedBlockSize-i], guessed, key, paddedPlainMsg[j:])
				if err != nil {
					t.Fatal("Could not build rainbow table", err)
				}
				// Going to guess the last byte of the block with the previously calculated rainbow map
				msg := make([]byte, 0, guessedBlockSize-i+len(paddedPlainMsg))
				msg = append(msg, prefix[0:guessedBlockSize-i]...)
				msg = append(msg, paddedPlainMsg[j:]...)
				encryptedMsg, err := oracleAesECB(msg, key)
				if err != nil {
					t.Fatal("An error occured while running the oracle", err)
				}
				key := fmt.Sprintf("%s", encryptedMsg[0:guessedBlockSize])

				v, ok := rainbow[key]
				if !ok {
					fmt.Println("value not found in rainbow", fmt.Sprintf("%q", encryptedMsg[0:len(prefix)]), v)
				} else {
					guessed = append(guessed, v...)
				}
			}
			guessedMsg = append(guessedMsg, guessed...)
		}
		fmt.Printf("guessedMsg = %s\n", guessedMsg)
		if !bytes.Equal(paddedPlainMsg, guessedMsg) {
			t.Fatalf("got = \n%q\n ; expected = \n%q\n", guessedMsg, paddedPlainMsg)
		}
	})
}

func Test_Challenge13_ECBCutAndPaste(t *testing.T) {
	challenge := struct {
		email                     string
		expectedSerializedProfile string
		expectedProfile           Profile
	}{
		email: "foo@bar.com",
		expectedSerializedProfile: "email=foo@bar.com&uid=10&role=user",
		expectedProfile: Profile{
			Email: "foo@bar.com",
			UID:   "10",
			Role:  "user",
		},
	}
	profile := NewProfile(challenge.email)
	t.Run("Profile Creation", func(t *testing.T) {
		if profile.Email != challenge.expectedProfile.Email ||
			profile.UID != challenge.expectedProfile.UID ||
			profile.Role != challenge.expectedProfile.Role {
			t.Fatal("New profile does not match expectation:", profile.Email, profile.UID, profile.Role)
		}
	})
	t.Run("Profile encoding", func(t *testing.T) {
		if profile.Encode() != challenge.expectedSerializedProfile {
			t.Fatal("Serialize profile do not match", profile.Encode(), "!=", challenge.expectedSerializedProfile)

		}
	})
	t.Run("Drop special char", func(t *testing.T) {
		if p := NewProfile("foo@bar.com&role=admin"); p.Email != "foo@bar.comroleadmin" {
			t.Fatal("new profile is not sanitized", p.Email)
		}
	})
	t.Run("AES encrypt", func(t *testing.T) {
		key := []byte("YELLOW SUBMARINE")
		fmt.Println("profile.Encode() = ", profile.Encode())
		encryptedProfile, err := profile.AESEncrypt(key)
		if err != nil {
			t.Fatal("Could not encrypt profile", err)
		}
		decryptedProfile, err := NewProfileFromEncrypted(encryptedProfile, key)
		if err != nil {
			t.Fatal("Could not create a profile from its encrypted representation:", err)
		}

		spew.Dump(decryptedProfile)
	})
	t.Run("craft a profile with admin", func(t *testing.T) {
		key := []byte("YELLOW SUBMARINE")
		fmt.Println("len('email=foo@bar.com&uid=10&role=user') =", len("email=foo@bar.com&uid=10&role=user"))
		fmt.Println("len('email=') =", len("email="))
		fmt.Println("len('email=foo@bar.co') = ", len("email=foo@bar.co"))
		// cut corner but in reality we should first guess the key size
		forgePaddedBlock, err := Pkcs7Pad([]byte("admin"), len(key))
		if err != nil {
			t.Fatal("Could not padd my generated bock:", err)
		}
		// the goal here is to craft an encrypted block in the form of `admin + >pkcs7 padding>`
		email := []byte("foo@bar.co")
		email = append(email, forgePaddedBlock...)
		profile := NewProfile(string(email))
		encryptedProfile1, err := (&profile).AESEncrypt(key)
		if err != nil {
			t.Fatal(err)
		}
		encryptedForgedBlock := []byte(encryptedProfile1)[16:32]

		// craft and encrypted profile with an email such as the value for the role key is in its own block
		fmt.Println("len('email=foo@baaar.com&uid=10&role=') = ", len("email=foo@baaar.com&uid=10&role="))
		userProfile := NewProfile("foo@baaar.com")
		encryptedAdmin, err := (&userProfile).AESEncrypt(key)
		if err != nil {
			t.Fatal(err)
		}

		encryptedAdmin = append(encryptedAdmin[0:32], encryptedForgedBlock...)
		adminProfile, err := NewProfileFromEncrypted(encryptedAdmin, key)
		if err != nil {
			t.Fatal(err)
		}

		if adminProfile.Role != "admin" {
			t.Fatal("Fail to crack the password")
		}
		fmt.Println("Created a role admin profile!!!!")
		spew.Dump(adminProfile)
	})
}
