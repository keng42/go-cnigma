// RSA used to sign/verify/encrypt/decrypt text using rsa
//
// created by keng42 @2020-12-04 21:42:22
//

package cnigma

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strings"
)

// RSA sturct stores private key and some configs
type RSA struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	Encoding   encodingType
}

func loadFile(filepath string) ([]byte, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, info.Size())
	_, err = io.ReadFull(f, buf)

	return buf, err
}

// LoadPrivateKey load private key from file
func LoadPrivateKey(filepath string) (*rsa.PrivateKey, error) {
	buf, err := loadFile(filepath)
	if err != nil {
		return nil, err
	}
	t := string(buf)

	// PKCS1
	if strings.HasPrefix(t, "-----BEGIN RSA PRIVATE KEY-----") {
		block, _ := pem.Decode(buf)
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	// PKCS8
	if strings.HasPrefix(t, "-----BEGIN PRIVATE KEY-----") {
		block, _ := pem.Decode(buf)
		parseResult, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key := parseResult.(*rsa.PrivateKey)
		return key, nil
	}

	return nil, errors.New("invalid private key file")
}

// LoadPublicKey load public key from file
func LoadPublicKey(filepath string) (*rsa.PublicKey, error) {
	buf, err := loadFile(filepath)
	if err != nil {
		return nil, err
	}
	t := string(buf)

	if strings.HasPrefix(t, "-----BEGIN PUBLIC KEY-----") {
		block, _ := pem.Decode(buf)
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}

	return nil, errors.New("invalid public key file")
}

// NewRSA returns a new RSA instance
func NewRSA(encoding encodingType) (*RSA, error) {
	if encoding == "" {
		encoding = Base64
	}
	return &RSA{Encoding: encoding}, nil
}

func (r *RSA) encode(buf []byte) string {
	if r.Encoding == Base64 {
		return base64.StdEncoding.EncodeToString(buf)
	}
	return hex.EncodeToString(buf)
}

func (r *RSA) decode(text string) ([]byte, error) {
	if r.Encoding == Base64 {
		return base64.StdEncoding.DecodeString(text)
	}
	return hex.DecodeString(text)
}

// Sign message with private key
func (r *RSA) Sign(msg string) (string, error) {
	if r.PrivateKey == nil {
		return "", errors.New("missing private key")
	}

	rng := rand.Reader
	hashed := sha256.Sum256([]byte(msg))

	signature, err := rsa.SignPKCS1v15(rng, r.PrivateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}

	return r.encode(signature), err
}

// Verify message with public key
func (r *RSA) Verify(msg, sig string) (bool, error) {
	pub := r.PublicKey
	if pub == nil && r.PrivateKey != nil {
		pub = &r.PrivateKey.PublicKey
	}
	if pub == nil {
		return false, errors.New("missing public key")
	}

	signature, err := r.decode(sig)
	if err != nil {
		return false, err
	}
	hashed := sha256.Sum256([]byte(msg))

	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], signature)
	return err == nil, nil
}

// Encrypt text with public key
func (r *RSA) Encrypt(plaintext string) (string, error) {
	pub := r.PublicKey
	if pub == nil && r.PrivateKey != nil {
		pub = &r.PrivateKey.PublicKey
	}
	if pub == nil {
		return "", errors.New("missing public key")
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte(plaintext), nil)
	if err != nil {
		return "", err
	}

	return r.encode(ciphertext), nil
}

// Decrypt text with private key
func (r *RSA) Decrypt(ciphertext string) (string, error) {
	if r.PrivateKey == nil {
		return "", errors.New("missing private key")
	}

	cipherBuf, err := r.decode(ciphertext)

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, r.PrivateKey, cipherBuf, nil)
	if err != nil {
		return "", nil
	}

	return string(plaintext), nil
}
