package gomat

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

func create_random_bytes(n int) []byte {
	out := make([]byte, n)
	rand.Read(out)
	return out
}

func id_to_bytes(id uint64) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, id)
	return b.Bytes()
}

func hmac_sha256_enc(in []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(in)
	return mac.Sum(nil)
}

func sha256_enc(in []byte) []byte {
	s := sha256.New()
	s.Write(in)
	return s.Sum(nil)
}

func hkdf_sha256(secret, salt, info []byte, size int) []byte {
	engine := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, size)
	if _, err := io.ReadFull(engine, key); err != nil {
		return []byte{}
	}
	return key
}
