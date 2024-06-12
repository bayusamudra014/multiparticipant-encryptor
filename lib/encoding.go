package lib

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
)

func MergeBytes(slices ...[]byte) []byte {
	result := make([]byte, 2)
	binary.LittleEndian.PutUint16(result, uint16(len(slices)))

	for _, slice := range slices {
		size := make([]byte, 8)
		binary.LittleEndian.PutUint64(size, uint64(len(slice)))

		data := append(size, slice...)
		result = append(result, data...)
	}

	return result
}

func SplitBytes(data []byte) [][]byte {
	count := binary.LittleEndian.Uint16(data[:2])
	data = data[2:]

	slices := make([][]byte, count)

	for i := 0; i < int(count); i++ {
		size := binary.LittleEndian.Uint64(data[:8])
		data = data[8:]

		slice := data[:size]
		data = data[size:]

		slices[i] = slice
	}

	return slices
}

func EncodeMap(data map[[4]byte][]byte) []byte {
	result := make([]byte, 2)
	binary.LittleEndian.PutUint16(result, uint16(len(data)))

	for key, value := range data {
		size := make([]byte, 8)
		binary.LittleEndian.PutUint64(size, uint64(len(value)))

		encoded := append(key[:], size...)
		encoded = append(encoded, value...)

		result = append(result, encoded...)
	}

	return result
}

func GetFromMapKey(key [4]byte, data []byte) []byte {
	compareKey := key[:]
	count := binary.LittleEndian.Uint16(data[:2])
	data = data[2:]

	var result []byte = nil

	for i := 0; i < int(count); i++ {
		currentKey := data[:4]
		size := binary.LittleEndian.Uint64(data[4:12])

		if subtle.ConstantTimeCompare(compareKey, currentKey) == 1 && result == nil {
			result = data[12 : 12+size]
		}

		data = data[12+size:]
	}

	return result
}

func DecodeMap(data []byte) map[[4]byte][]byte {
	count := binary.LittleEndian.Uint16(data[:2])
	data = data[2:]

	result := make(map[[4]byte][]byte)

	for i := 0; i < int(count); i++ {
		key := [4]byte(data[:4])
		size := binary.LittleEndian.Uint64(data[4:12])

		value := data[12 : 12+size]
		result[key] = value

		data = data[12+size:]
	}

	return result
}

func EncodePrivateEncryptionKey(key *ecdh.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

func DecodePrivateEncryptionKey(data []byte) (*ecdh.PrivateKey, error) {
	res, err := x509.ParsePKCS8PrivateKey(data)

	if err != nil {
		return nil, err
	}

	key := res.(*ecdsa.PrivateKey)
	return key.ECDH()
}

func EncodePublicEncryptionKey(key *ecdh.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key)
}

func DecodePublicEncryptionKey(data []byte) (*ecdh.PublicKey, error) {
	res, err := x509.ParsePKIXPublicKey(data)

	if err != nil {
		return nil, err
	}

	key := res.(*ecdsa.PublicKey)
	return key.ECDH()
}

func EncodePrivateSigningKey(key *ecdsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

func DecodePrivateSigningKey(data []byte) (*ecdsa.PrivateKey, error) {
	res, err := x509.ParsePKCS8PrivateKey(data)
	return res.(*ecdsa.PrivateKey), err
}

func EncodePublicSigningKey(key *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key)
}

func DecodePublicSigningKey(data []byte) (*ecdsa.PublicKey, error) {
	res, err := x509.ParsePKIXPublicKey(data)
	return res.(*ecdsa.PublicKey), err
}
