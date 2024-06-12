package crypto_test

import (
	"testing"

	lib "github.com/bayusamudra5502/multiparticipant-encryptor/lib/crypto"
	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	private, public, err := lib.GenerateSigningPair()
	assert.Nil(t, err)

	message := []byte("Hello, World!")
	signature, err := lib.SignBytes(private, message)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	valid := lib.VerifySignature(public, message, signature)
	assert.True(t, valid)
}
