package crypto_test

import (
	"testing"

	"github.com/bayusamudra5502/multiparticipant-encryptor/lib/crypto"
	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	private, public, err := crypto.GenerateSigningPair()
	assert.Nil(t, err)

	message := []byte("Hello, World!")
	signature, err := crypto.SignBytes(private, message)
	assert.Nil(t, err)
	assert.NotNil(t, signature)

	valid := crypto.VerifySignature(public, message, signature)
	assert.True(t, valid)
}
