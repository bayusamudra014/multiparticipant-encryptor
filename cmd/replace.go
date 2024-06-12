package cmd

import (
	"github.com/bayusamudra5502/multiparticipant-encryptor/lib"
	"github.com/bayusamudra5502/multiparticipant-encryptor/lib/cipher"
)

func ReplaceText(
	ciphertextPath string,
	newPlaintextPath string,
	outputPath string,
	privateKey string,
	password []byte,
	ownerPublicKeyPath string,
) error {
	ciphertext, err := lib.ReadBytesFromFile(ciphertextPath)
	if err != nil {
		return err
	}

	plaintext, err := lib.ReadBytesFromFile(newPlaintextPath)
	if err != nil {
		return err
	}

	encPrivateKey, _, err := ReadPrivateFile(privateKey, password)
	if err != nil {
		return err
	}

	_, ownerPublicKey, err := ReadPublicFile(ownerPublicKeyPath)
	if err != nil {
		return err
	}

	c := cipher.NewEncryptor(nil, encPrivateKey)
	result, err := c.Replace(ciphertext, plaintext, ownerPublicKey)

	if err != nil {
		return err
	}

	return lib.WriteBytesToFile(outputPath, result)
}
