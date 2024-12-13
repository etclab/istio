package keycurator

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// convert s to 16-bit number
func IdStringToNumber(s string) int32 {
	data := []byte(s)
	hash128 := md5.Sum(data) // 128 bits

	hash16 := hash128[0:2] // 16 bits
	number := binary.BigEndian.Uint16(hash16)

	return int32(number)
}

func GenerateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce: %w", err)
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}
