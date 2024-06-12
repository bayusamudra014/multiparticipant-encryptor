package encryptor

import (
	"crypto/ecdh"
	"crypto/ecdsa"
)

type Encryptor struct {
	participants  []Participant
	encryptionKey *ecdh.PrivateKey
	signingKey    *ecdsa.PrivateKey
}

func NewEncryptor(participants []Participant, encryptionKey *ecdh.PrivateKey, signingKey *ecdsa.PrivateKey) *Encryptor {
	return &Encryptor{
		participants:  participants,
		encryptionKey: encryptionKey,
		signingKey:    signingKey,
	}
}

func (e *Encryptor) AddParticipant(participant Participant) {
	e.participants = append(e.participants, participant)
}

func (e *Encryptor) RemoveParticipant(participant Participant) {
	for i, p := range e.participants {
		if p.Equals(&participant) {
			e.participants = append(e.participants[:i], e.participants[i+1:]...)
			break
		}
	}
}

func (e *Encryptor) Encrypt(data []byte) ([]byte, error) {
	// Implement this method

	return nil, nil
}
