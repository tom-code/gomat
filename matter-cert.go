package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"gomat/ca"
	"gomat/tlvdec"
	"log"
)


func CAMatterCert() []byte {

	cacert := ca.LoadCert("ca-cert.pem")
	pub := cacert.PublicKey.(*ecdsa.PublicKey)
	log.Println(pub)
	public_key := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
	/*public_key, err := x509.MarshalPKIXPublicKey(pub)

	if err != nil {
		panic(err)
	}*/

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


func CAMatterCert2() []byte {
	cacert := ca.LoadCert("ca-cert.pem")
	//cacert.Signature = []byte{}
	pub := cacert.PublicKey.(*ecdsa.PublicKey)
	log.Println(pub)
	public_key := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)

	//public_key := hex2bin("046fc35861a75f0b0d9d912009cbec15676f24678aeeab3dcb189c3e021500952c199dff8680bf0d3a4ee7c9f60048135fa210f2a4d60889ed2e6ca12166dc904e")


	var tlv3 TLVBuffer
	tlv3.writeAnonStruct()
	tlv3.writeOctetString(1, []byte{1}) // serial number
	tlv3.writeUInt(2, TYPE_UINT_1, 1) // signature algorithm
	//tlv3.writeUInt(3, TYPE_UINT_1, 1)
	tlv3.writeList(3)
	tlv3.writeUInt(20, TYPE_UINT_1, 1)
	tlv3.writeAnonStructEnd()
	tlv3.writeUInt(4, TYPE_UINT_4, 662774400)
	tlv3.writeUInt(5, TYPE_UINT_4, 978134400)
	tlv3.writeList(6)
	tlv3.writeUInt(20, TYPE_UINT_1, 1)
	tlv3.writeAnonStructEnd()
	tlv3.writeUInt(7, TYPE_UINT_1, 1)
	tlv3.writeUInt(8, TYPE_UINT_1, 1)
	//public key:
	//tlv3.writeOctetString(9, hex2bin("046fc35861a75f0b0d9d912009cbec15676f24678aeeab3dcb189c3e021500952c199dff8680bf0d3a4ee7c9f60048135fa210f2a4d60889ed2e6ca12166dc904e"))
	tlv3.writeOctetString(9, public_key)
	tlv3.writeList(10)
	tlv3.writeStruct(1)
	tlv3.writeBool(1, true) // isCA
	tlv3.writeAnonStructEnd()
	tlv3.writeUInt(2, TYPE_UINT_1, 96) // key-usage
	//id is 160bit sha1 of public key
	sh := sha1.New()
	sh.Write(public_key)
	sha := sh.Sum(nil)

	tlv3.writeOctetString(4, sha) // subject-key-id
	tlv3.writeOctetString(5, sha) // authority-key-id
	tlv3.writeAnonStructEnd()
	//tlv3.writeOctetString(11, hex2bin("4e313fcaea8b531b24f44ff1451368eea2018c89f787f39c0a52b85b08092fd475c285b99933caaa30e106e43bd129a9c65798a1ba5c06680e42f3104dd9336e"))
	fmt.Printf("signato: 4e313fcaea8b531b24f44ff1451368eea2018c89f787f39c0a52b85b08092fd475c285b99933caaa30e106e43bd129a9c65798a1ba5c06680e42f3104dd9336e\n")
	fmt.Printf("signat: %s\n", hex.EncodeToString(cacert.Signature))
	fmt.Printf("signat: %d\n", len(cacert.Signature))
	s1 := cacert.Signature[4:]
	s2 := s1[:32]
	s3 := s1[34:][:32]
	s4 := append(s2, s3...)
	fmt.Printf("signatx: %d %s\n", len(s4),hex.EncodeToString(s4))

	fmt.Printf("signat: %s\n", hex.EncodeToString(s2))
	fmt.Printf("signat: %s\n", hex.EncodeToString(s3))


	tlv3.writeOctetString(11, s4)
	tlv3.writeAnonStructEnd()
	return tlv3.data.Bytes()
}