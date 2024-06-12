package crypto_test

import (
	"crypto/rand"
	"testing"

	"github.com/bayusamudra5502/multiparticipant-encryptor/lib/crypto"
	"github.com/stretchr/testify/assert"
)

func TestAES(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)

	plaintext := []byte("Hello, World!")
	additionalInfo := []byte("additional info")

	ciphertext, err := crypto.EncryptAES(key, plaintext, additionalInfo)
	assert.Nil(t, err)
	assert.NotEqual(t, plaintext, ciphertext)
	assert.NotNil(t, plaintext, ciphertext)

	decrypted, err := crypto.DecryptAES(key, ciphertext, additionalInfo)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESDifferentInfo(t *testing.T) {
	key := make([]byte, 16)
	rand.Read(key)

	plaintext := []byte("Hello, World!")
	additionalInfo := []byte("additional info")

	ciphertext, err := crypto.EncryptAES(key, plaintext, additionalInfo)
	assert.Nil(t, err)
	assert.NotEqual(t, plaintext, ciphertext)
	assert.NotNil(t, plaintext, ciphertext)

	decrypted, err := crypto.DecryptAES(key, ciphertext, []byte("different info"))
	assert.NotNil(t, err)
	assert.Nil(t, decrypted)
}
