package cipher

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"errors"

	"github.com/bayusamudra5502/multiparticipant-encryptor/lib"
	"github.com/bayusamudra5502/multiparticipant-encryptor/lib/crypto"
)

type MultipartiCipher struct {
	readParticipants  []*Participant
	writeParticipants []*Participant
	signingKey        *ecdsa.PrivateKey
	decryptionKey     *ecdh.PrivateKey
}

func NewEncryptor(
	signingKey *ecdsa.PrivateKey,
	decryptionKey *ecdh.PrivateKey,
) *MultipartiCipher {
	return &MultipartiCipher{
		readParticipants: []*Participant{
			NewParticipant(decryptionKey.PublicKey()),
		},
		writeParticipants: []*Participant{
			NewParticipant(decryptionKey.PublicKey()),
		},
		signingKey:    signingKey,
		decryptionKey: decryptionKey,
	}
}

func (e *MultipartiCipher) SetReadParticipant(participant []*Participant) *MultipartiCipher {
	userParticipant := NewParticipant(e.decryptionKey.PublicKey())
	newParticipants := []*Participant{userParticipant}

	for _, p := range participant {
		if !p.Equals(userParticipant) {
			newParticipants = append(newParticipants, p)
		}
	}

	e.readParticipants = newParticipants
	return e
}

func (e *MultipartiCipher) SetWriteParticipant(participant []*Participant) *MultipartiCipher {
	userParticipant := NewParticipant(e.decryptionKey.PublicKey())
	newParticipants := []*Participant{userParticipant}

	for _, p := range participant {
		if !p.Equals(userParticipant) {
			newParticipants = append(newParticipants, p)
		}
	}

	e.writeParticipants = newParticipants

	return e
}

func (e *MultipartiCipher) Encrypt(data []byte) ([]byte, error) {
	if e.signingKey == nil {
		return nil, errors.New("signing key is required")
	}

	encryptionKey := make([]byte, 32)
	filePrivate, filePublic, err := crypto.GenerateSigningPair()

	if err != nil {
		return nil, err
	}

	readTable, err := GenerateParticipantTable(
		e.readParticipants,
		encryptionKey,
	)

	if err != nil {
		return nil, err
	}

	encoded, err := lib.EncodePrivateSigningKey(filePrivate)

	if err != nil {
		return nil, err
	}

	writeTable, err := GenerateParticipantTable(
		e.writeParticipants,
		encoded,
	)

	if err != nil {
		return nil, err
	}

	encodedPublic, err := lib.EncodePublicSigningKey(filePublic)

	if err != nil {
		return nil, err
	}

	mergedHead := lib.MergeBytes(readTable, writeTable, encodedPublic)
	ownerSignature, err := crypto.SignBytes(e.signingKey, mergedHead)
	if err != nil {
		return nil, err
	}

	encrypted, err := crypto.EncryptAES(encryptionKey, data, ownerSignature)
	if err != nil {
		return nil, err
	}

	mergedBody := lib.MergeBytes(readTable, writeTable, encodedPublic, ownerSignature, encrypted)
	fileSignature, err := crypto.SignBytes(filePrivate, mergedBody)

	if err != nil {
		return nil, err
	}

	allMerged := lib.MergeBytes(readTable, writeTable, encodedPublic, ownerSignature, encrypted, fileSignature)

	return allMerged, nil
}

func (e *MultipartiCipher) Verify(ownerPublic *ecdsa.PublicKey, data []byte) error {
	sepearated := lib.SplitBytes(data)

	if len(sepearated) != 6 {
		return errors.New("data has been tampered")
	}

	readTable := sepearated[0]
	writeTable := sepearated[1]
	encodedPublic := sepearated[2]
	ownerSignature := sepearated[3]
	encrypted := sepearated[4]
	fileSignature := sepearated[5]

	filePublicKey, err := lib.DecodePublicSigningKey(encodedPublic)

	if err != nil {
		return err
	}

	if ownerPublic != nil {
		if !crypto.VerifySignature(ownerPublic, lib.MergeBytes(readTable, writeTable, encodedPublic), ownerSignature) {
			return errors.New("file header signature is invalid")
		}
	}

	if !crypto.VerifySignature(filePublicKey, lib.MergeBytes(readTable, writeTable, encodedPublic, ownerSignature, encrypted), fileSignature) {
		return errors.New("file signature is invalid")
	}

	return nil
}

func (e *MultipartiCipher) Decrypt(data []byte, ownerPublic *ecdsa.PublicKey) ([]byte, error) {
	if e.decryptionKey == nil {
		return nil, errors.New("decryption key is required")
	}

	if err := e.Verify(ownerPublic, data); err != nil {
		return nil, err
	}

	sepearated := lib.SplitBytes(data)
	readTable := sepearated[0]
	encrypted := sepearated[4]
	ownerSignature := sepearated[3]

	encryptionKey, err := GetReadKey(readTable, e.decryptionKey)

	if err != nil {
		if err.Error() == "user doesn't have permission" {
			return nil, errors.New("user doesn't have permission to read")
		}

		return nil, err
	}

	result, err := crypto.DecryptAES(encryptionKey, encrypted, ownerSignature)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (e *MultipartiCipher) Replace(encrypted []byte, newData []byte, ownerPublic *ecdsa.PublicKey) ([]byte, error) {
	if e.decryptionKey == nil {
		return nil, errors.New("decryption key is required")
	}

	if err := e.Verify(ownerPublic, encrypted); err != nil {
		return nil, err
	}

	sepearated := lib.SplitBytes(encrypted)

	readTable := sepearated[0]
	writeTable := sepearated[1]
	encodedPublic := sepearated[2]
	ownerSignature := sepearated[3]

	encryptionKey, err := GetReadKey(readTable, e.decryptionKey)
	if err != nil {
		if err.Error() == "user doesn't have permission" {
			return nil, errors.New("user doesn't have permission to replace")
		}

		return nil, err
	}

	filePrivate, err := GetSigningKey(writeTable, e.decryptionKey)
	if err != nil {
		if err.Error() == "user doesn't have permission" {
			return nil, errors.New("user doesn't have permission to replace")
		}

		return nil, err
	}

	newEncrypted, err := crypto.EncryptAES(encryptionKey, newData, ownerSignature)
	if err != nil {
		return nil, err
	}

	mergedBody := lib.MergeBytes(readTable, writeTable, encodedPublic, ownerSignature, newEncrypted)
	fileSignature, err := crypto.SignBytes(filePrivate, mergedBody)

	if err != nil {
		return nil, err
	}

	allMerged := lib.MergeBytes(readTable, writeTable, encodedPublic, ownerSignature, newEncrypted, fileSignature)

	return allMerged, nil
}
