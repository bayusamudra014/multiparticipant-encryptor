package crypto_test

import (
	"testing"

	lib "github.com/bayusamudra5502/multiparticipant-encryptor/lib/crypto"
	"github.com/stretchr/testify/assert"
)

func TestGeneratePair(t *testing.T) {
	private, public, err := lib.GenerateECIESPair()

	assert.Nil(t, err)
	assert.NotNil(t, public)
	assert.NotNil(t, private)
}

func TestGenerateSharedKey(t *testing.T) {
	private, public, err := lib.GenerateECIESPair()
	assert.Nil(t, err)

	sharedKey, err := lib.GenerateSharedKey(public, private)
	assert.Nil(t, err)
	assert.NotNil(t, sharedKey)
}

func TestCalculatePublicHash(t *testing.T) {
	_, public, err := lib.GenerateECIESPair()
	assert.Nil(t, err)

	hash := lib.CalculatePublicHash(public, []byte("test"))
	assert.NotNil(t, hash)
}

func TestGenerateSigningPair(t *testing.T) {
	private, public, err := lib.GenerateSigningPair()

	assert.Nil(t, err)
	assert.NotNil(t, public)
	assert.NotNil(t, private)
}
