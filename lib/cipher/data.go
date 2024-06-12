package cipher

import (
	"crypto/ecdh"
)

type Participant struct {
	publicKey *ecdh.PublicKey
}

func NewParticipant(publicKey *ecdh.PublicKey) *Participant {
	return &Participant{publicKey: publicKey}
}

func (p *Participant) Equals(participant *Participant) bool {
	return p.publicKey.Equal(participant.publicKey)
}

func (p *Participant) PublicKey() *ecdh.PublicKey {
	return p.publicKey
}

func (p *Participant) Bytes() []byte {
	return p.publicKey.Bytes()
}
