package gomat

import (
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)


type Fabric struct {
	id uint64
	certificateManager CertificateManager
	ipk []byte
}

func (fabric Fabric) compressedFabric() []byte {
	capub := fabric.certificateManager.GetCaPublicKey()
	capublic_key := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)

	var fabric_big_endian bytes.Buffer
	binary.Write(&fabric_big_endian, binary.BigEndian, fabric.id)

	hkdfz := hkdf.New(sha256.New, capublic_key[1:], fabric_big_endian.Bytes(), []byte("CompressedFabric"))
	key := make([]byte, 8)
	if _, err := io.ReadFull(hkdfz, key); err != nil {
		panic(err)
	}
	//log.Printf("compressed fabric: %s\n", hex.EncodeToString(key))
	return key
}
func (fabric Fabric) make_ipk() []byte {
	hkdfz := hkdf.New(sha256.New, fabric.ipk, fabric.compressedFabric(), []byte("GroupKey v1.0"))
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdfz, key); err != nil {
		panic(err)
	}
	return key
}


func NewFabric(id uint64, certman CertificateManager) *Fabric {
	out:= &Fabric{
		id: id,
		certificateManager: certman,
		ipk: []byte{0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf},
	}
	return out
}
