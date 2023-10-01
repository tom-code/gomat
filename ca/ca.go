package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
)


func generate_and_store_key_ecdsa(name string) *ecdsa.PrivateKey {
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

func load_priv_key(file string) any {
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
func load_public_key(file string) any {
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

func store_cert(name string, cert_bytes []byte) {
	certBlock := pem.Block {
		Type: "CERTIFICATE",
		Bytes: cert_bytes,
	}
	err := os.WriteFile(name+"-cert.pem", pem.EncodeToMemory(&certBlock), 0600)
	if err != nil {
		panic(err)
	}
}

func Create_ca_cert() {

	generate_and_store_key_ecdsa("ca")
	pub := load_public_key("ca-public.pem")
	priv_ca := load_priv_key("ca-private.pem")

	
	subj := pkix.Name{
	}

	subj.ExtraNames = []pkix.AttributeTypeAndValue{
		{
			Type: asn1.ObjectIdentifier{1,3,6,1,4,1,37244,1,4},
			Value: "0000000000000001",
		},
	}
	//subj.CommonName = "aaa"
	var template x509.Certificate
	template.SignatureAlgorithm = x509.ECDSAWithSHA256
	template.Subject = subj
	template.IsCA = true
	template.SerialNumber = big.NewInt(1)
	template.Issuer = subj
	cert_bytes, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv_ca)
	if err != nil {
		panic(err)
	}
	store_cert("ca", cert_bytes)

	//ce := load_cert("ca-cert.pem")
	//log.Println(ce)
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