// GCM sturct and methods
//
// created by keng42 @2020-12-04 10:50:45
//

package cnigma

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
)

// GCM struct stores the default values required for the aes-gcm alogrithm and implements the AES interface
type GCM struct {
	Key      []byte
	Password string
	Version  []byte
	Encoding encodingType
}

// gcmCipher returns a aes-gcm cipher with provided key
func gcmCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm, nil
}

// EncryptBytes encrypt bytes using default key and specify password.
// If password is empty, use default password.
// The return value ciphertext consists of 2 bytes of version infomation,
// 14 bytes of nonce and encrypted data.
func (g *GCM) EncryptBytes(plaintext []byte, password string) ([]byte, error) {
	if password == "" {
		password = g.Password
	}
	passwordBuf := []byte(password)

	aad := append(g.Version, passwordBuf...)

	gcm, err := gcmCipher(g.Key)
	if err != nil {
		return nil, err
	}

	nonce, err := RandomBytes(gcmNonceSize)
	if err != nil {
		return nil, err
	}

	encrypted := gcm.Seal(nil, nonce, plaintext, aad)

	ciphertext := []byte{}
	ciphertext = append(ciphertext, g.Version...)
	ciphertext = append(ciphertext, nonce...)
	ciphertext = append(ciphertext, encrypted...)

	return ciphertext, nil
}

// EncryptText encrypt text by calling EncryptBytes
func (g *GCM) EncryptText(plaintext string, password string) (string, error) {
	cipherBuf, err := g.EncryptBytes([]byte(plaintext), password)
	if err != nil {
		return "", err
	}

	var ciphertext string
	if g.Encoding == Base64 {
		ciphertext = base64.StdEncoding.EncodeToString(cipherBuf)
	} else {
		ciphertext = hex.EncodeToString(cipherBuf)
	}

	return ciphertext, nil
}

// DecryptBytes decrypt bytes using default key and specify password.
// If password is empty, use default password.
func (g *GCM) DecryptBytes(ciphertext []byte, password string) ([]byte, error) {
	if password == "" {
		password = g.Password
	}
	passwordBuf := []byte(password)

	gcm, err := gcmCipher(g.Key)
	if err != nil {
		return nil, err
	}

	versionBuf := ciphertext[0:2]
	nonce := ciphertext[2:(2 + gcmNonceSize)]
	encrypted := ciphertext[(2 + gcmNonceSize):]
	aad := []byte{}
	aad = append(aad, versionBuf...)
	aad = append(aad, passwordBuf...)

	plain, err := gcm.Open(nil, nonce, encrypted, aad)
	if err != nil {
		return nil, err
	}

	return plain, nil
}

// DecryptText decrypt text by calling DecryptBytes
func (g *GCM) DecryptText(ciphertext string, password string) (string, error) {
	var cipherBuf []byte
	var err error
	if g.Encoding == Base64 {
		cipherBuf, err = base64.StdEncoding.DecodeString(ciphertext)
	} else {
		cipherBuf, err = hex.DecodeString(ciphertext)
	}
	if err != nil {
		return "", err
	}

	plainBuf, err := g.DecryptBytes(cipherBuf, password)
	if err != nil {
		return "", err
	}

	plaintext := string(plainBuf)

	return plaintext, nil
}

// EncryptFile encrypt the src file and save to the dst file using default key and specify password.
// The parameters src and dst are both file paths.
// Reading the entire file into memory and encrypting it may have performance issue,
// so divide the file info chunks of mulitiple fileBufferSize bytes and encrypt them separetely.
func (g *GCM) EncryptFile(src, dst, password string) error {
	inFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Since the encrypted output is 30 bytes larger than the input
	// (containning 2 bytes of version infomation, 12 bytes of nonce and 16 bytes of auth tag),
	// it's necessary to read 30 bytes less in order to decrypt the fileBufferSize byte at a time.
	buf := make([]byte, fileBufferSize-30)
	for {
		n, err := inFile.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if err == io.EOF {
			break
		}

		outBuf, err := g.EncryptBytes(buf[:n], password)
		if err != nil {
			return err
		}
		outFile.Write(outBuf)
	}

	return nil
}

// DecryptFile decrypt the src file and save to the dst file using default key and specify password.
// The parameters src and dst are both file paths.
// Since the encryption is split info separate chunks, the decryption has to be done separately.
func (g *GCM) DecryptFile(src, dst, password string) error {
	inFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer outFile.Close()

	buf := make([]byte, fileBufferSize)
	for {
		n, err := inFile.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		if err == io.EOF {
			break
		}

		outBuf, err := g.DecryptBytes(buf[:n], password)
		if err != nil {
			return err
		}
		outFile.Write(outBuf)
	}

	return nil
}
