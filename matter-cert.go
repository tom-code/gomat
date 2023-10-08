package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"gomat/ca"
	"gomat/tlvdec"
	"math/big"
	"strconv"
	"time"
)


func CAMatterCert() []byte {

	cacert := ca.LoadCert("ca-cert.pem")
	pub := cacert.PublicKey.(*ecdsa.PublicKey)
	public_key := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)


	var tlv TLVBuffer
	tlv.writeAnonStruct()
	tlv.writeOctetString(1, []byte{1})
	tlv.writeUInt(2, TYPE_UINT_1, 1)
	tlv.writeList(3)
	tlv.writeUInt(20, TYPE_UINT_1, 1)
	tlv.writeAnonStructEnd()
	tlv.writeUInt(4, TYPE_UINT_4, 662774400)
	tlv.writeUInt(5, TYPE_UINT_4, 978134400)
	tlv.writeList(6)
	tlv.writeUInt(20, TYPE_UINT_1, 1)
	tlv.writeAnonStructEnd()
	tlv.writeUInt(7, TYPE_UINT_1, 1)
	tlv.writeUInt(8, TYPE_UINT_1, 1)
	//public key:
	tlv.writeOctetString(9, public_key)
	tlv.writeList(10)
	tlv.writeStruct(1)
	tlv.writeBool(1, true) // isCA
	tlv.writeAnonStructEnd()
	tlv.writeUInt(2, TYPE_UINT_1, 96) // key-usage
	//id is 160bit sha1 of public key
	ide := sha1.New()
	ide.Write(public_key)
	ides := ide.Sum(nil)
	tlv.writeOctetString(4, ides) // subject-key-id
	tlv.writeOctetString(5, ides) // authority-key-id
	tlv.writeAnonStructEnd()
	//tlv.writeOctetString(11, hex2bin("4e313fcaea8b531b24f44ff1451368eea2018c89f787f39c0a52b85b08092fd475c285b99933caaa30e106e43bd129a9c65798a1ba5c06680e42f3104dd9336e"))
	tlv.writeOctetString(11, cacert.Signature)
	tlv.writeAnonStructEnd()

	enc := tlv.data.Bytes()
	dec := tlvdec.Decode(enc)
	dec.Dump(10)
	return tlv.data.Bytes()
}

type dsaSignature struct {
	R, S *big.Int
}

func CAConvertDNValue(in any) uint64 {
	v3, ok := in.(string)
	if !ok {
		panic("")
	}

	v4, err := strconv.ParseUint(v3, 16, 64)
	if err != nil {
		panic(err)
	}
	return v4
}

func CAConvertDN(in pkix.Name, out *TLVBuffer) {
	for _, extra := range in.Names {
		if extra.Type.Equal(asn1.ObjectIdentifier{1,3,6,1,4,1,37244,1,1}) { //node-id
			out.writeUInt(17, TYPE_UINT_1, CAConvertDNValue(extra.Value))
		}
		if extra.Type.Equal(asn1.ObjectIdentifier{1,3,6,1,4,1,37244,1,4}) { //matter-rcac-id
			out.writeUInt(20, TYPE_UINT_1, CAConvertDNValue(extra.Value))
		}
		if extra.Type.Equal(asn1.ObjectIdentifier{1,3,6,1,4,1,37244,1,5}) { //matter-fabric-id
			out.writeUInt(21, TYPE_UINT_1, CAConvertDNValue(extra.Value))
		}
	}
}

func MatterCert2(in *x509.Certificate) []byte {
	pub := in.PublicKey.(*ecdsa.PublicKey)
	public_key := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)

	//authority_key := in.AuthorityKeyId
	//authority_key := in.a
	cacert := ca.LoadCert("ca-cert.pem")
	capub := cacert.PublicKey.(*ecdsa.PublicKey)
	capublic_key := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)
	xide := sha1.New()
	xide.Write(capublic_key)
	xides := xide.Sum(nil)


	var tlv3 TLVBuffer
	tlv3.writeAnonStruct()
	tlv3.writeOctetString(1, in.SerialNumber.Bytes()) // serial number
	tlv3.writeUInt(2, TYPE_UINT_1, 1) // signature algorithm

	tlv3.writeList(3) // issuer
		CAConvertDN(in.Issuer, &tlv3)
	tlv3.writeAnonStructEnd()


	tlv3.writeUInt(4, TYPE_UINT_4, uint64(in.NotBefore.Unix()-946684800))
	tlv3.writeUInt(5, TYPE_UINT_4, uint64(in.NotAfter.Unix())-946684800)
	tlv3.writeList(6)  // subject
		CAConvertDN(in.Subject, &tlv3)
	tlv3.writeAnonStructEnd()
	tlv3.writeUInt(7, TYPE_UINT_1, 1)
	tlv3.writeUInt(8, TYPE_UINT_1, 1)
	//public key:
	tlv3.writeOctetString(9, public_key)
	tlv3.writeList(10)
		tlv3.writeStruct(1)
			tlv3.writeBool(1, in.IsCA) // isCA
		tlv3.writeAnonStructEnd()
		//tlv3.writeUInt(2, TYPE_UINT_1, 0x60) // key-usage

		//tlv3.writeArray(3)
		//	tlv3.writeRaw([]byte{0x04, 0x02, 0x04, 0x01})  // extended key-usage
		//tlv3.writeAnonStructEnd()

		tlv3.writeUInt(2, TYPE_UINT_1, uint64(in.KeyUsage)) // key-usage
		//id is 160bit sha1 of public key
		//sh := sha1.New()
		//sh.Write(public_key)
		//sha := sh.Sum(nil)
	
		if len(in.ExtKeyUsage) > 0 {
			tlv3.writeArray(3)
				tlv3.writeRaw([]byte{0x04, 0x02, 0x04, 0x01})  // extended key-usage
			tlv3.writeAnonStructEnd()
		}



		tlv3.writeOctetString(4, in.SubjectKeyId) // subject-key-id
		//tlv3.writeOctetString(5, authority_key) // authority-key-id
		tlv3.writeOctetString(5, xides) // authority-key-id
		//log.Printf("oooooooo keys %v %v\n",sha, authority_key)
	tlv3.writeAnonStructEnd()

	var signature dsaSignature
	asn1.Unmarshal(in.Signature, &signature)

	r := signature.R.Bytes()
	s := signature.S.Bytes()
	s4 := append(r, s...)
	tlv3.writeOctetString(11, s4)
	tlv3.writeAnonStructEnd()
	return tlv3.data.Bytes()
}
func CAMatterCert2() []byte {
	cacert := ca.LoadCert("ca-cert.pem")
	return MatterCert2(cacert)
}

func sign_cert(req *x509.CertificateRequest) *x509.Certificate {
	cacert := ca.LoadCert("ca-cert.pem")
	pub := ca.Load_public_key("ca-public.pem").(*ecdsa.PublicKey)
	priv_ca := ca.Load_priv_key("ca-private.pem")


	public_key_auth := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
	sh := sha1.New()
	sh.Write(public_key_auth)
	sha_auth := sh.Sum(nil)

	public_key_subj := req.PublicKey.(*ecdsa.PublicKey)
	public_key_subj2 := elliptic.Marshal(elliptic.P256(), public_key_subj.X, public_key_subj.Y)
	shp := sha1.New()
	shp.Write(public_key_subj2)
	sha_subj := shp.Sum(nil)

	subj := pkix.Name{
	}

	valname, err := asn1.MarshalWithParams("0000000000000002", "utf8")
	valname_fabric, err := asn1.MarshalWithParams("0000000000000010", "utf8")

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

	subj_issuer := pkix.Name{
	}

	valname_issuer, err := asn1.MarshalWithParams("0000000000000001", "utf8")

	subj_issuer.ExtraNames = []pkix.AttributeTypeAndValue{
		{
			Type: asn1.ObjectIdentifier{1,3,6,1,4,1,37244,1,4},
			Value: asn1.RawValue{FullBytes: valname_issuer},
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
	template.IsCA = false
	template.SerialNumber = big.NewInt(10001)
	template.Issuer = subj_issuer
	//template.KeyUsage = x509.KeyUsageCertSign
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

	cert_bytes, err := x509.CreateCertificate(rand.Reader, &template, cacert, public_key_subj, priv_ca)
	if err != nil {
		panic(err)
	}
	out_parsed, err := x509.ParseCertificate(cert_bytes)
	if err != nil {
		panic(err)
	}
	//store_cert("ca", cert_bytes)
	ca.Store_cert("user", cert_bytes)
	return out_parsed
}