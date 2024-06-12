package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"

	"github.com/bayusamudra5502/multiparticipant-encryptor/lib"
	"golang.org/x/crypto/pbkdf2"
)

func EncryptAES(key []byte, plaintext []byte, additionalInfo []byte) ([]byte, error) {
	aes, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aes)

	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := []byte{}
	ciphertext = gcm.Seal(ciphertext, nonce, plaintext, additionalInfo)

	joinedCiphertext := append(nonce, ciphertext...)

	return joinedCiphertext, nil
}

func DecryptAES(key []byte, ciphertext []byte, additionalInfo []byte) ([]byte, error) {
	aes, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aes)

	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext := []byte{}

	if plaintext, err = gcm.Open(plaintext, nonce, ciphertext, additionalInfo); err != nil {
		return nil, err
	}

	return plaintext, nil
}

func EncryptECIES(public *ecdh.PublicKey, plaintext []byte) ([]byte, error) {
	private, err := ecdh.P256().GenerateKey(rand.Reader)

	if err != nil {
		return nil, err
	}

	sharedKey, err := GenerateSharedKey(public, private)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 32)
	rand.Read(nonce)

	aesKey := pbkdf2.Key(sharedKey, nonce, 4096, 32, sha256.New)

	publicRandom := private.PublicKey().Bytes()
	encryptedData, err := EncryptAES(aesKey, plaintext, publicRandom)
	encryptedData = append(nonce, encryptedData...)

	if err != nil {
		return nil, err
	}

	return lib.MergeBytes(publicRandom, encryptedData), nil
}

func DecryptECIES(private *ecdh.PrivateKey, ciphertext []byte) ([]byte, error) {
	splitedData := lib.SplitBytes(ciphertext)
	publicRandom := splitedData[0]
	encryptedData := splitedData[1][32:]
	nonce := splitedData[1][:32]

	publicKey, err := ecdh.P256().NewPublicKey(publicRandom)

	if err != nil {
		return nil, err
	}

	sharedKey, err := GenerateSharedKey(publicKey, private)

	if err != nil {
		return nil, err
	}

	aesKey := pbkdf2.Key(sharedKey, nonce, 4096, 32, sha256.New)
	plaintext, err := DecryptAES(aesKey, encryptedData, publicRandom)

	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
