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
	dn_str, ok := in.(string)
	if !ok {
		return 0
	}

	dn_uint64, err := strconv.ParseUint(dn_str, 16, 64)
	if err != nil {
		return 0
	}
	return dn_uint64
}

func caConvertDN(in pkix.Name, out *mattertlv.TLVBuffer) {
	for _, extra := range in.Names {
		if extra.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 1}) { //node-id
			out.WriteUInt64(17, caConvertDNValue(extra.Value))
		}
		if extra.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 4}) { //matter-rcac-id
			out.WriteUInt64(20, caConvertDNValue(extra.Value))
		}
		if extra.Type.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 37244, 1, 5}) { //matter-fabric-id
			out.WriteUInt64(21, caConvertDNValue(extra.Value))
		}
	}
}

// SerializeCertificateIntoMatter serializes x509 certificate into matter certificate format.
// Matter certificate format is way how to make matter even more weird and complicated.
// Signature of matter vertificate must match signature of  certificate reencoded to DER encoding.
// This requires to handle very carefully order and presence of all elements in original x509.
func SerializeCertificateIntoMatter(fabric *Fabric, in *x509.Certificate) []byte {
	pub := in.PublicKey.(*ecdsa.PublicKey)
	public_key := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)

	cacert := fabric.CertificateManager.GetCaCertificate()
	capub := cacert.PublicKey.(*ecdsa.PublicKey)
	capublic_key := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)
	sha1_stream := sha1.New()
	sha1_stream.Write(capublic_key)
	ca_pubkey_hash := sha1_stream.Sum(nil)

	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteOctetString(1, in.SerialNumber.Bytes()) // serial number
	tlv.WriteUInt8(2, 1)                             // signature algorithm

	tlv.WriteList(3) // issuer
	caConvertDN(in.Issuer, &tlv)
	tlv.WriteAnonStructEnd()

	tlv.WriteUInt32(4, uint32(in.NotBefore.Unix()-946684800))
	tlv.WriteUInt32(5, uint32(in.NotAfter.Unix())-946684800)
	tlv.WriteList(6) // subject
	caConvertDN(in.Subject, &tlv)
	tlv.WriteAnonStructEnd()
	tlv.WriteUInt8(7, 1)
	tlv.WriteUInt8(8, 1)
	//public key:
	tlv.WriteOctetString(9, public_key)
	tlv.WriteList(10)
	tlv.WriteStruct(1)
	tlv.WriteBool(1, in.IsCA) // isCA
	tlv.WriteAnonStructEnd()

	tlv.WriteUInt(2, mattertlv.TYPE_UINT_1, uint64(in.KeyUsage)) // key-usage

	if len(in.ExtKeyUsage) > 0 {
		tlv.WriteArray(3)
		tlv.WriteRaw([]byte{0x04, 0x02, 0x04, 0x01}) // extended key-usage
		tlv.WriteAnonStructEnd()
	}

	tlv.WriteOctetString(4, in.SubjectKeyId) // subject-key-id
	tlv.WriteOctetString(5, ca_pubkey_hash)  // authority-key-id
	tlv.WriteAnonStructEnd()

	var signature dsaSignature
	asn1.Unmarshal(in.Signature, &signature)

	r := signature.R.Bytes()
	s := signature.S.Bytes()
	s4 := append(r, s...)
	tlv.WriteOctetString(11, s4)
	tlv.WriteAnonStructEnd()
	return tlv.Bytes()
}
