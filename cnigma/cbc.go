// CBC struct and methods
//
// created by keng42 @2020-12-04 13:09:05
//

package cnigma

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

// CBC struct stores the default values required for the aes-cbc alogrithm and implements the AES interface
type CBC struct {
	Key      []byte
	Version  []byte
	Encoding encodingType
}

// EncryptBytes encrypt bytes using default key.
// The return value ciphertext consists of 2 bytes of version infomation,
// 14 bytes of nonce and encrypted data.
func (c *CBC) EncryptBytes(plaintext []byte, _ string) ([]byte, error) {
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, err
	}

	plaintext = PKCS7Padding(plaintext, aes.BlockSize)

	iv, err := RandomBytes(cbcIVSize)
	if err != nil {
		return nil, err
	}

	encrypted := make([]byte, len(plaintext))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(encrypted, plaintext)

	ciphertext := []byte{}
	ciphertext = append(ciphertext, c.Version...)
	ciphertext = append(ciphertext, iv...)
	ciphertext = append(ciphertext, encrypted...)

	return ciphertext, nil
}

// EncryptText encrypt text by calling EncryptBytes.
func (c *CBC) EncryptText(plaintext string, _ string) (string, error) {
	cipherBuf, err := c.EncryptBytes([]byte(plaintext), "")
	if err != nil {
		return "", err
	}

	var ciphertext string
	if c.Encoding == Base64 {
		ciphertext = base64.StdEncoding.EncodeToString(cipherBuf)
	} else {
		ciphertext = hex.EncodeToString(cipherBuf)
	}

	return ciphertext, nil
}

// DecryptBytes decrypt bytes using default key.
func (c *CBC) DecryptBytes(ciphertext []byte, _ string) ([]byte, error) {
	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return nil, err
	}

	// versionBuf := ciphertext[0:2]
	iv := ciphertext[2:(2 + aes.BlockSize)]
	ciphertext = ciphertext[(2 + aes.BlockSize):]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	cbc := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	cbc.CryptBlocks(ciphertext, ciphertext)

	plaintext := PKCS7UnPadding(ciphertext)

	return plaintext, nil
}

// DecryptText decrypt text by calling DecryptBytes
func (c *CBC) DecryptText(ciphertext string, _ string) (string, error) {
	var cipherBuf []byte
	var err error
	if c.Encoding == Base64 {
		cipherBuf, err = base64.StdEncoding.DecodeString(ciphertext)
	} else {
		cipherBuf, err = hex.DecodeString(ciphertext)
	}
	if err != nil {
		return "", err
	}

	plainBuf, err := c.DecryptBytes(cipherBuf, "")
	if err != nil {
		return "", err
	}

	plaintext := string(plainBuf)

	return plaintext, nil
}

// EncryptFile encrypt the src file and save to the dst file using default key.
// The parameters src and dst are both file paths.
// Reading the entire file into memory and encrypting it may have performance issue,
// so divide the file info chunks of mulitiple fileBufferSize bytes and encrypt them one by one.
func (c *CBC) EncryptFile(src, dst, _ string) error {
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

	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return err
	}

	iv, err := RandomBytes(aes.BlockSize)
	if err != nil {
		return err
	}

	cbc := cipher.NewCBCEncrypter(block, iv)

	outFile.Write(c.Version)
	outFile.Write(iv)

	inBuf := make([]byte, fileBufferSize)
	for {
		n, err := inFile.Read(inBuf)
		if err != nil && err != io.EOF {
			return err
		}

		if n > 0 {
			if n < fileBufferSize {
				inBuf = PKCS7Padding(inBuf[0:n], aes.BlockSize)
			}
			outBuf := make([]byte, len(inBuf))
			cbc.CryptBlocks(outBuf, inBuf)
			outFile.Write(outBuf)
		}

		if err == io.EOF {
			break
		}
	}

	return nil
}

// DecryptFile decrypt the src file and save to the dst file using default key.
// The parameters src and dst are both file paths.
func (c *CBC) DecryptFile(src, dst, _ string) error {
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

	block, err := aes.NewCipher(c.Key)
	if err != nil {
		return err
	}

	inBuf := make([]byte, 2+aes.BlockSize)
	n, err := inFile.Read(inBuf)
	if err != nil && err != io.EOF {
		return err
	}
	if n != 2+aes.BlockSize {
		return errors.New("invalid cipher info")
	}

	// version := buf[0:2]
	iv := inBuf[2:]

	cbc := cipher.NewCBCDecrypter(block, iv)

	inBuf = make([]byte, fileBufferSize)
	for {
		n, err := inFile.Read(inBuf)
		if err != nil && err != io.EOF {
			return err
		}

		if n > 0 {

			outBuf := make([]byte, n)
			cbc.CryptBlocks(outBuf, inBuf[:n])

			if n < fileBufferSize {
				outBuf = PKCS7UnPadding(outBuf)
			}

			outFile.Write(outBuf)
		}

		if err == io.EOF {
			break
		}
	}

	return nil
}
