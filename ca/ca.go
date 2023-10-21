package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
)


func Generate_and_store_key_ecdsa(name string) *ecdsa.PrivateKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	privEC, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		panic(err)
	}
	privBlock := pem.Block {
		Type: "EC PRIVATE KEY",
		Bytes: privEC,
	}
	err = os.WriteFile(name+"-private.pem", pem.EncodeToMemory(&privBlock), 0600)
	if err != nil {
		panic(err)
	}
  
	pubPKIX, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	pubBlock := pem.Block {
		Type: "PUBLIC KEY",
		Bytes: pubPKIX,
	}
	err = os.WriteFile(name+"-public.pem", pem.EncodeToMemory(&pubBlock), 0600)
	if err != nil {
		panic(err)
	}
	return priv
}

func Load_priv_key(file string) any {
	data, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}
	pem_block, _ := pem.Decode(data)
	key, err := x509.ParseECPrivateKey(pem_block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}
func Load_public_key(file string) any {
	data, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}
	pem_block, _ := pem.Decode(data)
	key, err := x509.ParsePKIXPublicKey(pem_block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

func Store_cert(name string, cert_bytes []byte) {
	certBlock := pem.Block {
		Type: "CERTIFICATE",
		Bytes: cert_bytes,
	}
	err := os.WriteFile(name+"-cert.pem", pem.EncodeToMemory(&certBlock), 0600)
	if err != nil {
		panic(err)
	}
}

func LoadCert(file string) *x509.Certificate {
	data, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}
	pem_block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(pem_block.Bytes)
	if err != nil {
		panic(err)
	}
	return cert
}