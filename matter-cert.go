package gomat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strconv"

	"github.com/tom-code/gomat/mattertlv"
)

type dsaSignature struct {
	R, S *big.Int
}

func caConvertDNValue(in any) uint64 {
	v3, ok := in.(string)
	if !ok {
		return 0
	}

	v4, err := strconv.ParseUint(v3, 16, 64)
	if err != nil {
		return 0
	}
	return v4
}

func caConvertDN(in pkix.Name, out *mattertlv.TLVBuffer) {
	for _, extra := range in.Names {
		if extra.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}) { //node-id
			out.WriteUInt(17, mattertlv.TYPE_UINT_8, caConvertDNValue(extra.Value))
		}
		if extra.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 4}) { //matter-rcac-id
			out.WriteUInt(20, mattertlv.TYPE_UINT_8, caConvertDNValue(extra.Value))
		}
		if extra.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}) { //matter-fabric-id
			out.WriteUInt(21, mattertlv.TYPE_UINT_8, caConvertDNValue(extra.Value))
		}
	}
}

func SerializeCertificateIntoMatter(fabric *Fabric, in *x509.Certificate) []byte {
	pub := in.PublicKey.(*ecdsa.PublicKey)
	public_key := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)

	cacert := fabric.CertificateManager.GetCaCertificate()
	capub := cacert.PublicKey.(*ecdsa.PublicKey)
	capublic_key := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)
	xide := sha1.New()
	xide.Write(capublic_key)
	xides := xide.Sum(nil)

	var tlv3 mattertlv.TLVBuffer
	tlv3.WriteAnonStruct()
	tlv3.WriteOctetString(1, in.SerialNumber.Bytes()) // serial number
	tlv3.WriteUInt(2, mattertlv.TYPE_UINT_1, 1)       // signature algorithm

	tlv3.WriteList(3) // issuer
	caConvertDN(in.Issuer, &tlv3)
	tlv3.WriteAnonStructEnd()

	tlv3.WriteUInt(4, mattertlv.TYPE_UINT_4, uint64(in.NotBefore.Unix()-946684800))
	tlv3.WriteUInt(5, mattertlv.TYPE_UINT_4, uint64(in.NotAfter.Unix())-946684800)
	tlv3.WriteList(6) // subject
	caConvertDN(in.Subject, &tlv3)
	tlv3.WriteAnonStructEnd()
	tlv3.WriteUInt(7, mattertlv.TYPE_UINT_1, 1)
	tlv3.WriteUInt(8, mattertlv.TYPE_UINT_1, 1)
	//public key:
	tlv3.WriteOctetString(9, public_key)
	tlv3.WriteList(10)
	tlv3.WriteStruct(1)
	tlv3.WriteBool(1, in.IsCA) // isCA
	tlv3.WriteAnonStructEnd()

	tlv3.WriteUInt(2, mattertlv.TYPE_UINT_1, uint64(in.KeyUsage)) // key-usage

	if len(in.ExtKeyUsage) > 0 {
		tlv3.WriteArray(3)
		tlv3.WriteRaw([]byte{0x04, 0x02, 0x04, 0x01}) // extended key-usage
		tlv3.WriteAnonStructEnd()
	}

	tlv3.WriteOctetString(4, in.SubjectKeyId) // subject-key-id
	tlv3.WriteOctetString(5, xides)           // authority-key-id
	tlv3.WriteAnonStructEnd()

	var signature dsaSignature
	asn1.Unmarshal(in.Signature, &signature)

	r := signature.R.Bytes()
	s := signature.S.Bytes()
	s4 := append(r, s...)
	tlv3.WriteOctetString(11, s4)
	tlv3.WriteAnonStructEnd()
	return tlv3.Bytes()
}
