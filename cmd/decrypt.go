package cmd

import (
	"fmt"

	"github.com/bayusamudra5502/multiparticipant-encryptor/lib"
	"github.com/bayusamudra5502/multiparticipant-encryptor/lib/cipher"
)

func Decrypt(
	inputPath string,
	outputPath string,
	privateKey string,
	password []byte,
	ownerPublicKeyPath string,
) error {
	ciphertext, err := lib.ReadBytesFromFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read ciphertext: %w", err)
	}

	encPrivateKey, _, err := ReadPrivateFile(privateKey, password)
	if err != nil {
		return fmt.Errorf("failed to read private key: %w", err)
	}

	_, ownerPublicKey, err := ReadPublicFile(ownerPublicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read owner public key: %w", err)
	}

	c := cipher.NewEncryptor(nil, encPrivateKey)
	res, err := c.Decrypt(ciphertext, ownerPublicKey)

	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	return lib.WriteBytesToFile(outputPath, res)
}
