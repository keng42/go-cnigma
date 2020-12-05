package cnigma

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func ExampleNewAES() {
	aesgcm, err := NewAES("gcm", "", "my-password", "base64")
	if err != nil {
		log.Fatal(err)
	}

	ciphertext, err := aesgcm.EncryptText("hello world @ 2020", "")
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := aesgcm.DecryptText(ciphertext, "")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(plaintext)
	// Output: hello world @ 2020
}

func fileHash(filepath string) string {
	f, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	return hex.EncodeToString(h.Sum(nil))
}

func ExampleCBC_EncryptFile() {
	aescbc, err := NewAES("cbc", "", "", "base64")
	if err != nil {
		log.Fatal(err)
	}

	err = aescbc.EncryptFile("testdata/xxy007.png", "testdata/xxy007.png.cbc", "")
	if err != nil {
		log.Fatal(err)
	}

	err = aescbc.DecryptFile("testdata/xxy007.png.cbc", "testdata/xxy007.cbc.png", "")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(fileHash("testdata/xxy007.cbc.png"))
	// Output: a818b30f2ddbb4bd5d77acaa33bb037ba0b92add5159c8b49c9923295bdaf59a
}

func TestGCMText(t *testing.T) {
	aesgcm, err := NewAES("gcm", "", "my-password", "base64")
	assert.Nil(t, err)

	plaintext := "hello world @ 2020"
	ciphertext, err := aesgcm.EncryptText(plaintext, "")
	assert.Nil(t, err)

	decrypted, err := aesgcm.DecryptText(ciphertext, "")
	assert.Nil(t, err)
	assert.Equal(t, plaintext, decrypted)

	// ciphertext from cnigma-ts
	decrypted, err = aesgcm.DecryptText("AQLV3eYPTOMhNec2Q69aY0Y3dOhbSTW4HMgmFucRugX5y9eY2nvXeMl/Zy8PVOpV", "")
	assert.Nil(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestCBCText(t *testing.T) {
	aescbc, err := NewAES("cbc", "", "my-password", "base64")
	assert.Nil(t, err)

	plain := "hello world @ 2020"
	ciphertext, err := aescbc.EncryptText(plain, "")
	assert.Nil(t, err)

	decrypted, err := aescbc.DecryptText(ciphertext, "")
	assert.Nil(t, err)
	assert.Equal(t, plain, decrypted)
}

func TestCBCFile(t *testing.T) {
	aescbc, err := NewAES("cbc", "", "my-password", "base64")
	assert.Nil(t, err)

	err = aescbc.EncryptFile("testdata/xxy007.png", "testdata/xxy007.png.cbc", "")
	assert.Nil(t, err)

	err = aescbc.DecryptFile("testdata/xxy007.png.cbc", "testdata/xxy007.cbc.png", "")
	assert.Nil(t, err)
}

func TestGCMFile(t *testing.T) {
	aesgcm, err := NewAES("gcm", "", "my-password", "base64")
	assert.Nil(t, err)

	err = aesgcm.EncryptFile("testdata/xxy007.png", "testdata/xxy007.png.gcm", "")
	assert.Nil(t, err)

	err = aesgcm.DecryptFile("testdata/xxy007.png.gcm", "testdata/xxy007.gcm.png", "")
	assert.Nil(t, err)
}

func TestGCMPadding(t *testing.T) {
	aesgcm, err := NewAES("gcm", "", "my-password", "base64")
	assert.Nil(t, err)

	for i := 1; i <= 17; i++ {
		ciphertext, err := aesgcm.EncryptBytes(make([]byte, i), "")
		assert.Nil(t, err)
		fmt.Println(i, len(ciphertext)-14-i)
	}
}

func TestFilePath(t *testing.T) {
	files, err := ioutil.ReadDir("testdata")
	assert.Nil(t, err)

	for _, file := range files {
		fmt.Println(file.Name())
	}
}
