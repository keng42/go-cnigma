// AES used to encrypt/decrypt text or file using aes-gcm or aes-cbc
//
// created by keng42 @2020-12-04 10:30:05
//

package cnigma

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// AES interface used to provide a unified list of methods for aes-gcm and aes-cbc
type AES interface {
	EncryptBytes(plain []byte, password string) ([]byte, error)
	DecryptBytes(cipher []byte, password string) ([]byte, error)
	EncryptText(plain string, password string) (string, error)
	DecryptText(cipher string, password string) (string, error)
	EncryptFile(src, dst, password string) error
	DecryptFile(src, dst, password string) error
}

type modeType string
type encodingType string

// Constants used to limit NewAES's parameter values
const (
	ModeGCM    modeType     = "gcm"
	ModeCBC    modeType     = "cbc"
	Base64     encodingType = "base64"
	Hex        encodingType = "hex"
	DefaultKey string       = "7At16p/dyonmDW3ll9Pl1bmCsWEACxaIzLmyC0ZWGaE="
)

const (
	gcmNonceSize   = 12        // standard nonce length for gcm mode
	gmcAuthTagSize = 16        // default auth tag length for gcm mode
	cbcIVSize      = 16        // standard iv length for cbc mode
	fileBufferSize = 16 * 1024 // default buffer size when reading file
)

// NewAES returns a GCM or CBC instance depending on the mode parameter.
// It's provide default value for all parameters except for the password in gcm mode.
func NewAES(
	mode modeType,
	key string,
	password string,
	encoding encodingType,
) (AES, error) {

	if mode == "" {
		mode = ModeGCM
	}
	if mode == ModeGCM && password == "" {
		return nil, errors.New("password is required in gcm mode")
	}
	if mode != ModeGCM && mode != ModeCBC {
		return nil, errors.New("only support gcm and cbc mode")
	}

	if key == "" {
		key = DefaultKey
	}
	keyBuf, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}

	keySize := len(keyBuf) * 8
	if keySize != 256 {
		if mode == ModeCBC {
			return nil, errors.New("key requires a 256-bit base64 encoded string with cbc mode")
		}
		if keySize != 128 && keySize != 192 {
			return nil, errors.New("key requires a 128-bit, 192-bit or 256-bit base64 encoded string")
		}
	}

	if encoding == "" {
		encoding = Base64
	}

	if mode == ModeGCM {
		return &GCM{
			Key:      keyBuf,
			Password: password,
			Version:  []byte{0x01, 0x03},
			Encoding: encoding,
		}, nil
	}
	return &CBC{
		Key:      keyBuf,
		Version:  []byte{0x01, 0x04},
		Encoding: encoding,
	}, nil
}

// NewGCM returns a GCM instance
func NewGCM(
	key string,
	password string,
	encoding encodingType,
) (AES, error) {
	return NewAES(ModeGCM, key, password, encoding)
}

// NewCBC returns a CBC instance
func NewCBC(
	key string,
	encoding encodingType,
) (AES, error) {
	return NewAES(ModeCBC, key, "", encoding)
}

// RandomBytes generate random bytes with specify size
func RandomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// PKCS7Padding pad block using pkcs7
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding unpad block using pkcs7
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
