package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
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