package cmd

import (
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
	res, err := c.Decrypt(ciphertext, ownerPublicKey)

	if err != nil {
		return err
	}

	return lib.WriteBytesToFile(outputPath, res)
}
