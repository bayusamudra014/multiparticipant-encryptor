package encryptor

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"

	"github.com/bayusamudra5502/multiparticipant-encryptor/lib"
	"github.com/bayusamudra5502/multiparticipant-encryptor/lib/crypto"
)

func GenerateParticipantTable(e Encryptor, encryptionKey []byte) ([]byte, error) {
	data := map[[4]byte][]byte{}
	nonce := make([]byte, 32)
	rand.Read(nonce)

	for _, participant := range e.participants {
		hash := crypto.CalculatePublicHash(&participant.publicKey, nonce)
		res, err := crypto.EncryptECIES(&participant.publicKey, encryptionKey)

		if err != nil {
			return nil, err
		}

		data[hash] = res
	}

	table := lib.EncodeMap(data)

	return lib.MergeBytes(nonce, table), nil
}

func GetReadKey(readKeyTable []byte, privateKey *ecdh.PrivateKey) ([]byte, error) {
	publicKey := privateKey.PublicKey()
	data := lib.SplitBytes(readKeyTable)

	nonce := data[0]
	table := data[1]

	hash := crypto.CalculatePublicHash(publicKey, nonce)
	encryptedKey := lib.GetFromMapKey(hash, table)

	return crypto.DecryptECIES(privateKey, encryptedKey)
}

func GetSigningKey(signingKeyTable []byte, privateKey *ecdh.PrivateKey) (*ecdsa.PrivateKey, error) {
	publicKey := privateKey.PublicKey()
	data := lib.SplitBytes(signingKeyTable)

	nonce := data[0]
	table := data[1]

	hash := crypto.CalculatePublicHash(publicKey, nonce)
	encryptedKey := lib.GetFromMapKey(hash, table)

	key, err := crypto.DecryptECIES(privateKey, encryptedKey)

	if err != nil {
		return nil, err
	}

	res, err := lib.DecodePrivateSigningKey(key)
	return res, err
}
