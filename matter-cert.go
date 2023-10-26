package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strconv"
)


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
			out.writeUInt(17, TYPE_UINT_8, CAConvertDNValue(extra.Value))
		}
		if extra.Type.Equal(asn1.ObjectIdentifier{1,3,6,1,4,1,37244,1,4}) { //matter-rcac-id
			out.writeUInt(20, TYPE_UINT_8, CAConvertDNValue(extra.Value))
		}
		if extra.Type.Equal(asn1.ObjectIdentifier{1,3,6,1,4,1,37244,1,5}) { //matter-fabric-id
			out.writeUInt(21, TYPE_UINT_8, CAConvertDNValue(extra.Value))
		}
	}
}

func MatterCert2(fabric *Fabric, in *x509.Certificate) []byte {
	pub := in.PublicKey.(*ecdsa.PublicKey)
	public_key := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)

	cacert := fabric.certificateManager.GetCaCertificate()
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


		tlv3.writeUInt(2, TYPE_UINT_1, uint64(in.KeyUsage)) // key-usage

	
		if len(in.ExtKeyUsage) > 0 {
			tlv3.writeArray(3)
				tlv3.writeRaw([]byte{0x04, 0x02, 0x04, 0x01})  // extended key-usage
			tlv3.writeAnonStructEnd()
		}



		tlv3.writeOctetString(4, in.SubjectKeyId) // subject-key-id
		tlv3.writeOctetString(5, xides) // authority-key-id
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
