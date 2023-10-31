package gomat

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
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)


func cert_id_to_name(id uint64) string {
	return fmt.Sprintf("%d", id)
}

type CertManager struct {
	fabric uint64
	ca_certificate *x509.Certificate
	ca_private_key *ecdsa.PrivateKey
}

func NewFileCertManager(fabric uint64) *CertManager {
	return &CertManager{
		fabric: fabric,
	}
}
func (cm *CertManager)GetCaPublicKey() ecdsa.PublicKey {
	return cm.ca_private_key.PublicKey
}
func (cm *CertManager)GetCaCertificate() *x509.Certificate {
	return cm.ca_certificate
}
func (cm *CertManager)Load() error {
	_, err := os.Stat("pem/ca-private.pem")
	if err != nil {
		log.Printf("can't open CA key. continue anyway %s\n", err.Error())
		return nil
	}
	anykey, err := load_priv_key("pem/ca-private.pem")
	if err != nil {
		return err
	}
	cm.ca_private_key = anykey.(*ecdsa.PrivateKey)
	cm.ca_certificate, err = loadCert("pem/ca-cert.pem")
	return err
}

func (cm *CertManager)GetCertificate(id uint64) (*x509.Certificate, error) {
	return loadCert("pem/"+cert_id_to_name(id)+"-cert.pem")
}
func (cm *CertManager)GetPrivkey(id uint64) (*ecdsa.PrivateKey, error) {
	pk, err := load_priv_key("pem/"+cert_id_to_name(id)+"-private.pem")
	if err != nil {
		return nil, err
	}
	return pk.(*ecdsa.PrivateKey), nil
}

func (cm *CertManager)CreateUser(node_id uint64) error {
	id := fmt.Sprintf("%d", node_id)
	privkey, err := generate_and_store_key_ecdsa("pem/"+id)
	if err != nil {
		return err
	}
	cm.SignCertificate(&privkey.PublicKey, node_id)
	return nil
}
func (cm *CertManager)SignCertificate(user_pubkey *ecdsa.PublicKey, node_id uint64) (*x509.Certificate, error) {


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

	node_id_string := fmt.Sprintf("%016X", node_id)
	valname, err := asn1.MarshalWithParams(node_id_string, "utf8")
	fabric_string := fmt.Sprintf("%016X", cm.fabric)
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
		return nil, err
	}
	out_parsed, err := x509.ParseCertificate(cert_bytes)
	if err != nil {
		return nil, err
	}
	store_cert("pem/"+cert_id_to_name(node_id), cert_bytes)
	log.Printf("Signed certificate for node 0x%x\n", node_id)
	return out_parsed, nil
}

func (cm *CertManager)BootstrapCa() {

	_, err := os.Stat("pem/ca-private.pem")
	if err == nil {
		log.Printf("CA private key already present - skipping bootstrap\n")
		return
	}

	generate_and_store_key_ecdsa("pem/ca")
	cm.create_ca_cert()
}

func (cm *CertManager)create_ca_cert() error {
	pubany, err := load_public_key("pem/ca-public.pem")
	if err != nil {
		return err
	}
	pub := pubany.(*ecdsa.PublicKey)
	priv_ca, err := load_priv_key("pem/ca-private.pem")
	if err != nil {
		return err
	}


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
		return err
	}
	store_cert("pem/ca", cert_bytes)
	log.Println("CA certificate was created")
	return nil
}



func generate_and_store_key_ecdsa(name string) (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	privEC, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	privBlock := pem.Block {
		Type: "EC PRIVATE KEY",
		Bytes: privEC,
	}
	err = os.WriteFile(name+"-private.pem", pem.EncodeToMemory(&privBlock), 0600)
	if err != nil {
		return nil, err
	}
  
	pubPKIX, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	pubBlock := pem.Block {
		Type: "PUBLIC KEY",
		Bytes: pubPKIX,
	}
	err = os.WriteFile(name+"-public.pem", pem.EncodeToMemory(&pubBlock), 0600)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func load_priv_key(file string) (any, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pem_block, _ := pem.Decode(data)
	key, err := x509.ParseECPrivateKey(pem_block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
func load_public_key(file string) (any, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pem_block, _ := pem.Decode(data)
	key, err := x509.ParsePKIXPublicKey(pem_block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
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

func loadCert(file string) (*x509.Certificate, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pem_block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(pem_block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}