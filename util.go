package main

import "crypto/rand"


func create_random_bytes(n int) []byte {
	out := make([]byte, n)
	rand.Read(out)
	return out
}