package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"gomat/ca"
	"gomat/tlvdec"
	"log"
	"math/big"
	"strconv"
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
		if extra.Type.Equal(asn1.ObjectIdentifier{1,3,6,1,4,1,37244,1,4}) { //matter-rcac-id
			out.writeUInt(20, TYPE_UINT_1, CAConvertDNValue(extra.Value))
		}
	}
}

func CAMatterCert2() []byte {
	cacert := ca.LoadCert("ca-cert.pem")
	pub := cacert.PublicKey.(*ecdsa.PublicKey)
	public_key := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)

	authority_key := cacert.AuthorityKeyId


	var tlv3 TLVBuffer
	tlv3.writeAnonStruct()
	tlv3.writeOctetString(1, cacert.SerialNumber.Bytes()) // serial number
	tlv3.writeUInt(2, TYPE_UINT_1, 1) // signature algorithm

	tlv3.writeList(3) // issuer
		CAConvertDN(cacert.Issuer, &tlv3)
		//tlv3.writeUInt(20, TYPE_UINT_1, 1)  // matter-rcac-id
	tlv3.writeAnonStructEnd()


	tlv3.writeUInt(4, TYPE_UINT_4, uint64(cacert.NotBefore.Unix()-946684800))
	tlv3.writeUInt(5, TYPE_UINT_4, uint64(cacert.NotAfter.Unix())-946684800)
	tlv3.writeList(6)  // subject
		CAConvertDN(cacert.Subject, &tlv3)
		//tlv3.writeUInt(20, TYPE_UINT_1, 1)  // matter-rcac-id
	tlv3.writeAnonStructEnd()
	tlv3.writeUInt(7, TYPE_UINT_1, 1)
	tlv3.writeUInt(8, TYPE_UINT_1, 1)
	//public key:
	tlv3.writeOctetString(9, public_key)
	tlv3.writeList(10)
		tlv3.writeStruct(1)
			tlv3.writeBool(1, true) // isCA
		tlv3.writeAnonStructEnd()
		tlv3.writeUInt(2, TYPE_UINT_1, 0x60) // key-usage
		//id is 160bit sha1 of public key
		sh := sha1.New()
		sh.Write(public_key)
		sha := sh.Sum(nil)

		tlv3.writeOctetString(4, sha) // subject-key-id
		//tlv3.writeOctetString(5, sha) // authority-key-id
		tlv3.writeOctetString(5, authority_key) // authority-key-id
		log.Printf("oooooooo keys %v %v\n",sha, authority_key)
	tlv3.writeAnonStructEnd()

	var signature dsaSignature
	asn1.Unmarshal(cacert.Signature, &signature)

	r := signature.R.Bytes()
	s := signature.S.Bytes()

	//s1 := cacert.Signature[4:]
	//s2 := s1[:32]
	//s3 := s1[34:][:32]
	//s4 := append(s2, s3...)
	s4 := append(r, s...)


	tlv3.writeOctetString(11, s4)
	tlv3.writeAnonStructEnd()
	return tlv3.data.Bytes()
}