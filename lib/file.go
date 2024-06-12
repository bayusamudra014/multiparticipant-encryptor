package lib

import (
	"os"
)

func WriteBytesToFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

func ReadBytesFromFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
