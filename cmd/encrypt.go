package cmd

import (
	"encoding/json"

	"github.com/bayusamudra5502/multiparticipant-encryptor/lib"
	"github.com/bayusamudra5502/multiparticipant-encryptor/lib/cipher"
)

type AccessControl struct {
	PublicKeyPath string `json:"path"`
	ReadAccess    bool   `json:"read_acl"`
	ReplaceAccess bool   `json:"replace_acl"`
}

type AccessControlList struct {
	AccessControls []AccessControl `json:"acl"`
}

func ParseACL(aclFile string) ([]AccessControl, error) {
	data, err := lib.ReadBytesFromFile(aclFile)

	if err != nil {
		return nil, err
	}

	acl := &AccessControlList{}
	if json.Unmarshal(data, acl) != nil {
		return nil, err
	}

	return acl.AccessControls, nil
}

func EncryptFile(
	inputPath string,
	outputPath string,
	privateKey string,
	password []byte,
	acls []AccessControl,
) error {
	plaintext, err := lib.ReadBytesFromFile(inputPath)
	if err != nil {
		return err
	}

	readAccess := []*cipher.Participant{}
	writeAccess := []*cipher.Participant{}

	for _, acl := range acls {
		publicKey, _, err := ReadPublicFile(acl.PublicKeyPath)
		if err != nil {
			return err
		}

		if acl.ReadAccess {
			readAccess = append(readAccess, cipher.NewParticipant(publicKey))
		}

		if acl.ReplaceAccess {
			writeAccess = append(writeAccess, cipher.NewParticipant(publicKey))
		}
	}

	_, signPrivate, err := ReadPrivateFile(privateKey, password)
	if err != nil {
		return err
	}

	c := cipher.NewEncryptor(signPrivate, nil).
		SetReadParticipant(readAccess).
		SetWriteParticipant(writeAccess)

	res, err := c.Encrypt(plaintext)

	if err != nil {
		return err
	}

	return lib.WriteBytesToFile(outputPath, res)
}
