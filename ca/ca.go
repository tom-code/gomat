package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"time"
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
	pub := load_public_key("ca-public.pem").(*ecdsa.PublicKey)
	priv_ca := load_priv_key("ca-private.pem")


	public_key := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
	sh := sha1.New()
	sh.Write(public_key)
	sha := sh.Sum(nil)
	
	subj := pkix.Name{
	}

	valname, err := asn1.MarshalWithParams("0000000000000001", "utf8")

	subj.ExtraNames = []pkix.AttributeTypeAndValue{
		{
			Type: asn1.ObjectIdentifier{1,3,6,1,4,1,37244,1,4},
			Value: asn1.RawValue{FullBytes: valname},
		},
	}
	//subj.CommonName = "aaa"
	var template x509.Certificate
	template.Version = 3
	//template.BasicConstraintsValid = true
	template.SignatureAlgorithm = x509.ECDSAWithSHA256
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().AddDate(1, 0, 0)
	template.Subject = subj
	template.IsCA = true
	template.SerialNumber = big.NewInt(10000)
	template.Issuer = subj
	//template.KeyUsage = x509.KeyUsageCertSign
	template.ExtraExtensions = []pkix.Extension{
		{
			Id: asn1.ObjectIdentifier{2,5,29,19}, // basic constraints
			Critical: true,
			Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff},
		},
		{
			Id: asn1.ObjectIdentifier{2,5,29,15},  // keyUsage
			Critical: true,
			Value: []byte{3,2,1,6},
		},
		{
			Id: asn1.ObjectIdentifier{2,5,29,14},  //subjectKeyId
			Critical: false,
			Value: append([]byte{0x04,0x14}, sha...),
		},
		{
			Id: asn1.ObjectIdentifier{2,5,29,35},  // authorityKeyId
			Critical: false,
			Value: append([]byte{0x30, 0x16, 0x80, 0x14}, sha...),
		},
	}

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