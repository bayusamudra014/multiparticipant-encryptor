package cmd

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/bayusamudra5502/multiparticipant-encryptor/lib"
	"github.com/bayusamudra5502/multiparticipant-encryptor/lib/crypto"
	"golang.org/x/crypto/hkdf"
)

func GenerateKeyPairFile(publicKeyPath string, privateKeyPath string, privatePassword []byte) error {
	privateKey, publicKey, err := GenerateKeyPair((privatePassword))
	if err != nil {
		return err
	}

	err = lib.WriteBytesToFile(privateKeyPath, privateKey)
	if err != nil {
		return err
	}

	return lib.WriteBytesToFile(publicKeyPath, publicKey)
}

func ReadPrivateFile(privateKeyPath string, privatePassword []byte) (*ecdh.PrivateKey, *ecdsa.PrivateKey, error) {
	privateKeyData, err := lib.ReadBytesFromFile(privateKeyPath)
	if err != nil {
		return nil, nil, err
	}

	return ReadPrivateKey(privateKeyData, privatePassword)
}

func ReadPublicFile(publicKeyPath string) (*ecdh.PublicKey, *ecdsa.PublicKey, error) {
	publicKeyData, err := lib.ReadBytesFromFile(publicKeyPath)
	if err != nil {
		return nil, nil, err
	}

	return ReadPublicKey(publicKeyData)
}

func GenerateKeyPair(privatePassword []byte) ([]byte, []byte, error) {
	encPrivateKey, encPublicKey, err := crypto.GenerateECIESPair()

	if err != nil {
		return nil, nil, err
	}

	signPrivateKey, signPublicKey, err := crypto.GenerateSigningPair()

	if err != nil {
		return nil, nil, err
	}

	encodedEncPrivate, err := lib.EncodePrivateEncryptionKey(encPrivateKey)

	if err != nil {
		return nil, nil, err
	}

	encodedSignPrivate, err := lib.EncodePrivateSigningKey(signPrivateKey)

	if err != nil {
		return nil, nil, err
	}

	encodedEncPublic, err := lib.EncodePublicEncryptionKey(encPublicKey)

	if err != nil {
		return nil, nil, err
	}

	encodedSignPublic, err := lib.EncodePublicSigningKey(signPublicKey)

	if err != nil {
		return nil, nil, err
	}

	mergedPrivateKey := lib.MergeBytes(encodedEncPrivate, encodedSignPrivate)
	mergedPublicKey := lib.MergeBytes(encodedEncPublic, encodedSignPublic)

	salt := make([]byte, 32)
	rand.Read(salt)

	aesKey := hkdf.Extract(sha256.New, privatePassword, salt)

	encryptedPrivateKey, err := crypto.EncryptAES(aesKey[:16], mergedPrivateKey, salt)
	if err != nil {
		return nil, nil, err
	}

	addedSalt := append(encryptedPrivateKey, salt...)
	return addedSalt, mergedPublicKey, nil
}

func ReadPrivateKey(privateKeyData []byte, privatePassword []byte) (*ecdh.PrivateKey, *ecdsa.PrivateKey, error) {
	if len(privateKeyData) < 32 {
		return nil, nil, errors.New("invalid private key data")
	}

	encryptedPrivateKey := privateKeyData[:len(privateKeyData)-32]
	encryptedSalt := privateKeyData[len(privateKeyData)-32:]

	aesKey := hkdf.Extract(sha256.New, privatePassword, encryptedSalt)
	decryptedPrivateKey, err := crypto.DecryptAES(aesKey[:16], encryptedPrivateKey, encryptedSalt)

	if err != nil {
		return nil, nil, err
	}

	splitedPrivateKey := lib.SplitBytes(decryptedPrivateKey)
	encryption := splitedPrivateKey[0]
	signing := splitedPrivateKey[1]

	encPrivateKey, err := lib.DecodePrivateEncryptionKey(encryption)
	if err != nil {
		return nil, nil, err
	}

	signPrivateKey, err := lib.DecodePrivateSigningKey(signing)
	if err != nil {
		return nil, nil, err
	}

	return encPrivateKey, signPrivateKey, nil
}

func ReadPublicKey(publicKeyData []byte) (*ecdh.PublicKey, *ecdsa.PublicKey, error) {
	splitedPublicKey := lib.SplitBytes(publicKeyData)
	encryption := splitedPublicKey[0]
	signing := splitedPublicKey[1]

	encPublicKey, err := lib.DecodePublicEncryptionKey(encryption)
	if err != nil {
		return nil, nil, err
	}

	signPublicKey, err := lib.DecodePublicSigningKey(signing)
	if err != nil {
		return nil, nil, err
	}

	return encPublicKey, signPublicKey, nil
}
