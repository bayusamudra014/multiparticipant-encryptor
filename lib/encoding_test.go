package lib_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/bayusamudra5502/multiparticipant-encryptor/lib"
	"github.com/stretchr/testify/assert"
)

func TestMergeSplit(t *testing.T) {
	data := [][]byte{}

	for i := 0; i < 100; i++ {
		length, err := rand.Int(rand.Reader, big.NewInt(1000000))
		assert.Nil(t, err)

		payload := make([]byte, length.Int64())
		rand.Read(payload)

		data = append(data, payload)
	}

	merged := lib.MergeBytes(data...)
	splited := lib.SplitBytes(merged)

	assert.Equal(t, len(data), len(splited))
	assert.Equal(t, data, splited)
}

func TestEncodeDecodeMap(t *testing.T) {
	data := map[[4]byte][]byte{}

	for i := 0; i < 100; i++ {
		length, err := rand.Int(rand.Reader, big.NewInt(1000000))
		assert.Nil(t, err)

		payload := make([]byte, length.Int64())
		rand.Read(payload)

		key := [4]byte{}
		rand.Read(key[:])

		data[key] = payload
	}

	encoded := lib.EncodeMap(data)
	decoded := lib.DecodeMap(encoded)

	assert.Equal(t, len(data), len(decoded))
	assert.Equal(t, data, decoded)
}

func TestFindDataWithKey(t *testing.T) {
	data := map[[4]byte][]byte{}

	for i := 0; i < 100; i++ {
		length, err := rand.Int(rand.Reader, big.NewInt(1000000))
		assert.Nil(t, err)

		payload := make([]byte, length.Int64())
		rand.Read(payload)

		key := [4]byte{}
		rand.Read(key[:])

		data[key] = payload
	}

	encoded := lib.EncodeMap(data)

	for key, value := range data {
		result := lib.GetFromMapKey(key, encoded)
		assert.Equal(t, value, result)
	}
}

func TestFindDataWithKeyNotFound(t *testing.T) {
	data := map[[4]byte][]byte{}

	for i := 0; i < 100; i++ {
		length, err := rand.Int(rand.Reader, big.NewInt(1000000))
		assert.Nil(t, err)

		payload := make([]byte, length.Int64())
		rand.Read(payload)

		key := [4]byte{}
		rand.Read(key[:])

		data[key] = payload
	}

	key := [4]byte{}
	rand.Read(key[:])

	delete(data, key)

	encoded := lib.EncodeMap(data)

	result := lib.GetFromMapKey(key, encoded)
	assert.Nil(t, result)
}
