package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
)

func GenerateECIESPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	private, err := ecdh.P256().GenerateKey(rand.Reader)

	if err != nil {
		return nil, nil, err
	}

	public := private.PublicKey()
	return private, public, nil
}

func GenerateSharedKey(public *ecdh.PublicKey, private *ecdh.PrivateKey) ([]byte, error) {
	sharedKey, err := private.ECDH(public)
	if err != nil {
		return nil, err
	}

	return sharedKey, nil
}

func CalculatePublicHash(public *ecdh.PublicKey, nonce []byte) []byte {
	hash := sha256.New()
	hash.Write(public.Bytes())
	hash.Write(nonce)

	return hash.Sum(nil)
}

func GenerateSigningPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return nil, nil, err
	}

	public := &private.PublicKey
	return private, public, nil
}
