package cmd_test

import (
	"crypto/rand"
	"testing"

	"github.com/bayusamudra5502/multiparticipant-encryptor/cmd"
	"github.com/stretchr/testify/assert"
)

func TestGenerateKeyPair(t *testing.T) {
	password := make([]byte, 32)
	_, err := rand.Read(password)
	assert.Nil(t, err)

	privateKey, publicKey, err := cmd.GenerateKeyPair(password)
	assert.Nil(t, err)

	encPrivate, signPrivate, err := cmd.ReadPrivateKey(privateKey, password)
	assert.Nil(t, err)
	assert.NotNil(t, encPrivate)
	assert.NotNil(t, signPrivate)

	encPublic, signPublic, err := cmd.ReadPublicKey(publicKey)
	assert.Nil(t, err)
	assert.NotNil(t, encPublic)
	assert.NotNil(t, signPublic)
}

func TestReadWithBadPass(t *testing.T) {
	password := make([]byte, 32)
	_, err := rand.Read(password)
	assert.Nil(t, err)

	password2 := make([]byte, 32)
	_, err = rand.Read(password2)
	assert.Nil(t, err)

	privateKey, _, err := cmd.GenerateKeyPair(password)
	assert.Nil(t, err)

	encPrivate, signPrivate, err := cmd.ReadPrivateKey(privateKey, password2)
	assert.NotNil(t, err)
	assert.Nil(t, encPrivate)
	assert.Nil(t, signPrivate)

}
