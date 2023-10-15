package main

// requirements:
// - create, manage, own CA certificate and private key
// - sign device certificate (no need to store?)
// - create/sign/own controller certificate and private key
//    - this is key of user accessing devices
//    - it can be admin or moreregular user
//    - we may want to support multiple of them

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"gomat/ca"
	"math/big"
	"time"
)


type CertManager struct {
	fabric uint64
	ca_certificate *x509.Certificate
	ca_private_key *ecdsa.PrivateKey
}

func NewCertManager() *CertManager {
	return &CertManager{
		fabric: 0x10,
	}
}

func (cm *CertManager)load() {
	cm.ca_private_key = ca.Load_priv_key("pem/ca-private.pem").(*ecdsa.PrivateKey)
	cm.ca_certificate = ca.LoadCert("pem/ca-cert.pem")
}

func (cm *CertManager)get_certificate(name string) *x509.Certificate {
	return ca.LoadCert("pem/"+name+"-cert.pem")
}
func (cm *CertManager)get_privkey(name string) *ecdsa.PrivateKey {
	return ca.Load_priv_key("pem/"+name+"-private.pem").(*ecdsa.PrivateKey)
}

func (cm *CertManager)create_user(node_id uint64, name string) {
	privkey := ca.Generate_and_store_key_ecdsa("pem/"+name)
	cm.sign_cert(&privkey.PublicKey, node_id, "pem/"+name)
}
func (cm *CertManager)sign_cert(user_pubkey *ecdsa.PublicKey, node_id uint64, name string) *x509.Certificate {
	//cacert := ca.LoadCert("ca-cert.pem")
	//pub := ca.Load_public_key("ca-public.pem").(*ecdsa.PublicKey)
	//priv_ca := ca.Load_priv_key("ca-private.pem")


	public_key_auth := elliptic.Marshal(elliptic.P256(), cm.ca_private_key.PublicKey.X, cm.ca_private_key.PublicKey.Y)
	sh := sha1.New()
	sh.Write(public_key_auth)
	sha_auth := sh.Sum(nil)

	public_key_subj := user_pubkey
	public_key_subj2 := elliptic.Marshal(elliptic.P256(), public_key_subj.X, public_key_subj.Y)
	shp := sha1.New()
	shp.Write(public_key_subj2)
	sha_subj := shp.Sum(nil)

	subj := pkix.Name{
	}

	node_id_string := fmt.Sprintf("%016x", node_id)
	valname, err := asn1.MarshalWithParams(node_id_string, "utf8")
	fabric_string := fmt.Sprintf("%016x", cm.fabric)
	valname_fabric, err := asn1.MarshalWithParams(fabric_string, "utf8")

	subj.ExtraNames = []pkix.AttributeTypeAndValue{
		{
			Type: asn1.ObjectIdentifier{1,3,6,1,4,1,37244,1,1},
			Value: asn1.RawValue{FullBytes: valname},
		},
		{
			Type: asn1.ObjectIdentifier{1,3,6,1,4,1,37244,1,5},
			Value: asn1.RawValue{FullBytes: valname_fabric},
		},
	}

	var template x509.Certificate
	template.Version = 3
	template.SignatureAlgorithm = x509.ECDSAWithSHA256
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().AddDate(1, 0, 0)
	template.Subject = subj
	template.IsCA = false
	template.SerialNumber = big.NewInt(10001)

	extkeyusa, _ := hex.DecodeString("301406082B0601050507030206082B06010505070301")
	template.ExtraExtensions = []pkix.Extension{
		{
			Id: asn1.ObjectIdentifier{2,5,29,19}, // basic constraints
			Critical: true,
			Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff},
		},
		{
			Id: asn1.ObjectIdentifier{2,5,29,15},  // keyUsage
			Critical: true,
			Value: []byte{3,2,7,0x80},
		},
		{
			Id: asn1.ObjectIdentifier{2,5,29,37},  // ExtkeyUsage
			Critical: true,
			Value: extkeyusa,
		},
		{
			Id: asn1.ObjectIdentifier{2,5,29,14},  //subjectKeyId
			Critical: false,
			Value: append([]byte{0x04,0x14}, sha_subj...),
		},
		{
			Id: asn1.ObjectIdentifier{2,5,29,35},  // authorityKeyId
			Critical: false,
			Value: append([]byte{0x30, 0x16, 0x80, 0x14}, sha_auth...),
		},
	}

	cert_bytes, err := x509.CreateCertificate(rand.Reader, &template, cm.ca_certificate, public_key_subj, cm.ca_private_key)
	if err != nil {
		panic(err)
	}
	out_parsed, err := x509.ParseCertificate(cert_bytes)
	if err != nil {
		panic(err)
	}
	ca.Store_cert(name, cert_bytes)
	return out_parsed
}

func bootstrap_ca() {
	ca.Generate_and_store_key_ecdsa("pem/ca")
	Create_ca_cert()
}

func Create_ca_cert() {

	pub := ca.Load_public_key("pem/ca-public.pem").(*ecdsa.PublicKey)
	priv_ca := ca.Load_priv_key("pem/ca-private.pem")


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
	var template x509.Certificate
	template.Version = 3
	template.SignatureAlgorithm = x509.ECDSAWithSHA256
	template.NotBefore = time.Now()
	template.NotAfter = time.Now().AddDate(1, 0, 0)
	template.Subject = subj
	template.IsCA = true
	template.SerialNumber = big.NewInt(10000)
	template.Issuer = subj

	// extensions must be in matter correct order
	// for this reason they must appear in this list
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
	ca.Store_cert("pem/ca", cert_bytes)
}