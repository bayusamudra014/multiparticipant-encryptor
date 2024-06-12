package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"

	"github.com/bayusamudra5502/multiparticipant-encryptor/lib"
)

func SignBytes(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])

	if err != nil {
		return nil, err
	}

	signature := lib.MergeBytes(r.Bytes(), s.Bytes())
	return signature, nil
}

func VerifySignature(publicKey *ecdsa.PublicKey, data []byte, signature []byte) bool {
	digest := sha256.Sum256(data)
	signatureData := lib.SplitBytes(signature)

	r := &big.Int{}
	r.SetBytes(signatureData[0])

	s := &big.Int{}
	s.SetBytes(signatureData[1])

	return ecdsa.Verify(publicKey, digest[:], r, s)
}
