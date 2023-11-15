package gomat

import (
	"bytes"
	"crypto/elliptic"
	"encoding/binary"
)


// Fabric structure represents matter Fabric.
// Its main parameters are Id of fabric and certificate manager.
type Fabric struct {
	id                 uint64
	CertificateManager CertificateManager
	ipk                []byte
}

func (fabric Fabric) Id() uint64 {
	return fabric.id
}

// CompressedFabric returns Compressed Fabric Identifier which is used to identify fabric
// in matter protocol.
func (fabric Fabric) CompressedFabric() []byte {
	capub := fabric.CertificateManager.GetCaPublicKey()
	capublic_key := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)

	var fabric_big_endian bytes.Buffer
	binary.Write(&fabric_big_endian, binary.BigEndian, fabric.id)

	key := hkdf_sha256(capublic_key[1:], fabric_big_endian.Bytes(), []byte("CompressedFabric"), 8)
	return key
}
func (fabric Fabric) make_ipk() []byte {
	key := hkdf_sha256(fabric.ipk, fabric.CompressedFabric(), []byte("GroupKey v1.0"), 16)
	return key
}

// NewFabric constructs new Fabric object.
func NewFabric(id uint64, certman CertificateManager) *Fabric {
	out := &Fabric{
		id:                 id,
		CertificateManager: certman,
		ipk:                []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf},
	}
	return out
}
