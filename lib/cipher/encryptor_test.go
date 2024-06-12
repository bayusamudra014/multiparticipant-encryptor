package cipher_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/bayusamudra5502/multiparticipant-encryptor/lib/cipher"
	"github.com/bayusamudra5502/multiparticipant-encryptor/lib/crypto"
	"github.com/stretchr/testify/assert"
)

func generateParticipant(n int) ([]*cipher.Participant, []*ecdh.PrivateKey, error) {
	participants := []*cipher.Participant{}
	keys := []*ecdh.PrivateKey{}

	for i := 0; i < n; i++ {
		privateKey, publicKey, err := crypto.GenerateECIESPair()

		if err != nil {
			return nil, nil, err
		}

		participants = append(participants, cipher.NewParticipant(publicKey))
		keys = append(keys, privateKey)
	}

	return participants, keys, nil
}

func TestCipherByOwner(t *testing.T) {
	ownerPrivateEncrypt, _, err := crypto.GenerateECIESPair()
	assert.Nil(t, err)

	ownerPrivateSign, ownerPublicSign, err := crypto.GenerateSigningPair()
	assert.Nil(t, err)

	readPublic, _, err := generateParticipant(5)
	assert.Nil(t, err)

	writePublic, _, err := generateParticipant(5)
	assert.Nil(t, err)

	message := make([]byte, 1024*1024)
	rand.Read(message)

	c := cipher.NewEncryptor(ownerPrivateSign, ownerPrivateEncrypt).SetReadParticipant(readPublic).SetWriteParticipant(writePublic)

	encrypted, err := c.Encrypt(message)
	assert.Nil(t, err)

	decrypted, err := c.Decrypt(encrypted, ownerPublicSign)
	assert.Nil(t, err)
	assert.Equal(t, message, decrypted)
}

func TestCipherByPair(t *testing.T) {
	ownerPrivateEncrypt, _, err := crypto.GenerateECIESPair()
	assert.Nil(t, err)

	ownerPrivateSign, ownerPublicSign, err := crypto.GenerateSigningPair()
	assert.Nil(t, err)

	readPublic, readPrivate, err := generateParticipant(5)
	assert.Nil(t, err)

	writePublic, writePrivate, err := generateParticipant(5)
	assert.Nil(t, err)

	message := make([]byte, 1024*1024)
	rand.Read(message)

	c := cipher.NewEncryptor(ownerPrivateSign, ownerPrivateEncrypt).
		SetReadParticipant(readPublic).
		SetWriteParticipant(writePublic)

	encrypted, err := c.Encrypt(message)
	assert.Nil(t, err)

	c = cipher.NewEncryptor(nil, readPrivate[0])
	result, err := c.Decrypt(encrypted, ownerPublicSign)
	assert.Nil(t, err)
	assert.Equal(t, message, result)

	c = cipher.NewEncryptor(nil, writePrivate[0])
	result, err = c.Decrypt(encrypted, ownerPublicSign)
	assert.NotNil(t, err)
	assert.Nil(t, result)
}

func TestCipherReplace(t *testing.T) {
	ownerPrivateEncrypt, _, err := crypto.GenerateECIESPair()
	assert.Nil(t, err)

	ownerPrivateSign, ownerPublicSign, err := crypto.GenerateSigningPair()
	assert.Nil(t, err)

	readPublic, readPrivate, err := generateParticipant(5)
	assert.Nil(t, err)

	writePublic, writePrivate, err := generateParticipant(4)
	assert.Nil(t, err)

	writePublic = append([]*cipher.Participant{readPublic[0]}, writePublic...)
	writePrivate = append([]*ecdh.PrivateKey{readPrivate[0]}, writePrivate...)

	message := make([]byte, 1024*1024)
	rand.Read(message)

	c1 := cipher.
		NewEncryptor(ownerPrivateSign, ownerPrivateEncrypt).
		SetReadParticipant(readPublic).
		SetWriteParticipant(writePublic)

	encrypted, err := c1.Encrypt(message)
	assert.Nil(t, err)

	// Change by user
	newMessage := make([]byte, 1024*1024)
	rand.Read(newMessage)

	c2 := cipher.NewEncryptor(nil, writePrivate[0])
	newEncrypted, err := c2.Replace(encrypted, newMessage, ownerPublicSign)
	assert.Nil(t, err)
	assert.Nil(t, c2.Verify(ownerPublicSign, newEncrypted))

	// Read by owner
	newDecryptedMessage, err := c1.Decrypt(newEncrypted, ownerPublicSign)
	assert.Nil(t, err)
	assert.NotNil(t, newDecryptedMessage)

	assert.Equal(t, newMessage, newDecryptedMessage)
	assert.NotEqual(t, message, newDecryptedMessage)

	// Read by updater
	newDecryptedMessage, err = c2.Decrypt(newEncrypted, ownerPublicSign)
	assert.Nil(t, err)
	assert.Equal(t, newMessage, newDecryptedMessage)
	assert.NotEqual(t, message, newDecryptedMessage)

	// Read by other
	c3 := cipher.NewEncryptor(nil, readPrivate[3])
	newDecryptedMessage, err = c3.Decrypt(newEncrypted, ownerPublicSign)
	assert.Nil(t, err)
	assert.Equal(t, newMessage, newDecryptedMessage)
	assert.NotEqual(t, message, newDecryptedMessage)

	// Read by write only
	c4 := cipher.NewEncryptor(nil, writePrivate[3])
	newDecryptedMessage, err = c4.Decrypt(newEncrypted, ownerPublicSign)
	assert.NotNil(t, err)
	assert.Nil(t, newDecryptedMessage)

}
