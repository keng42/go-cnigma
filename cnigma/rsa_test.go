package cnigma

import (
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadPrivateKey(t *testing.T) {
	priv, err := LoadPrivateKey("testdata/rsa-private-pkcs8.key")
	assert.Nil(t, err)

	fmt.Println(priv)
}

func TestRSA(t *testing.T) {
	priv, err := LoadPrivateKey("testdata/rsa-private-pkcs8.key")
	assert.Nil(t, err)

	r, _ := NewRSA(Hex)
	r.PrivateKey = priv
	r.PublicKey = &priv.PublicKey

	msg := "hello world @ 2020"

	sig, err := r.Sign(msg)
	assert.Nil(t, err)
	fmt.Println("sig", sig)

	verified, err := r.Verify(msg, sig)
	assert.Nil(t, err)
	fmt.Println("verified", verified)

	ciphertext, err := r.Encrypt(msg)
	assert.Nil(t, err)
	fmt.Println("ciphertext", ciphertext)

	plaintext, err := r.Decrypt(ciphertext)
	assert.Nil(t, err)
	fmt.Println("plaintext", plaintext)
}

func ExampleNewRSA() {
	priv, err := LoadPrivateKey("testdata/rsa-private-pkcs8.key")
	if err != nil {
		log.Fatal(err)
	}

	r, _ := NewRSA(Hex)
	r.PrivateKey = priv
	r.PublicKey = &priv.PublicKey

	msg := "hello world @ 2020"

	sig, err := r.Sign(msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("sig", sig)

	verified, err := r.Verify(msg, sig)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("verified", verified)

	ciphertext, err := r.Encrypt(msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ciphertext", ciphertext)

	plaintext, err := r.Decrypt(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("plaintext", plaintext)
}
