package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"gomat/ca"
	"io"
	"log"

	"golang.org/x/crypto/hkdf"
)


func compressedFabric() []byte {
	cacert := ca.LoadCert("ca-cert.pem")
	capub := cacert.PublicKey.(*ecdsa.PublicKey)
	capublic_key := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)

	
	hkdfz := hkdf.New(sha256.New, capublic_key[1:], []byte{0,0,0,0,0,0,0,0x10}, []byte("CompressedFabric"))
	key := make([]byte, 8)
	if _, err := io.ReadFull(hkdfz, key); err != nil {
		panic(err)
	}
	log.Printf("compressed fabric: %s\n", hex.EncodeToString(key))
	return key
}


func make_ipk() []byte {
	ipk := []byte{0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf}
	hkdfz := hkdf.New(sha256.New, ipk, compressedFabric(), []byte("GroupKey v1.0"))
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdfz, key); err != nil {
		panic(err)
	}
	return key
}

func genSigma1(privkey *ecdh.PrivateKey) []byte{
	var tlv TLVBuffer
	tlv.writeAnonStruct()
	
	initiatorRandom := make([]byte, 32)
	rand.Read(initiatorRandom)
	tlv.writeOctetString(1, initiatorRandom)

	sessionId := 222
	tlv.writeUInt(2, TYPE_UINT_2, uint64(sessionId))

	var destination_message bytes.Buffer
	destination_message.Write(initiatorRandom)
	cacert := ca.LoadCert("ca-cert.pem")
	capub := cacert.PublicKey.(*ecdsa.PublicKey)
	capublic_key := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)

	destination_message.Write(capublic_key)

	var fabric uint64
	fabric = 0x10
	binary.Write(&destination_message, binary.LittleEndian, fabric)

	var node uint64
	node = 2
	binary.Write(&destination_message, binary.LittleEndian, node)

	ipk := []byte{0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf}
	hkdfz := hkdf.New(sha256.New, ipk, compressedFabric(), []byte("GroupKey v1.0"))
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdfz, key); err != nil {
		panic(err)
	}
	log.Printf("group key %s\n", hex.EncodeToString(key))


	log.Printf("dest id %s\n", hex.EncodeToString(destination_message.Bytes()))

	mac := hmac.New(sha256.New, key)
	mac.Write(destination_message.Bytes())
	destinationIdentifier := mac.Sum(nil)
	log.Printf("hmaec %s", hex.EncodeToString(destinationIdentifier))

	tlv.writeOctetString(3, destinationIdentifier)


	tlv.writeOctetString(4, privkey.PublicKey().Bytes())
	tlv.writeAnonStructEnd()
	return tlv.data.Bytes()
}

func genSigma1Req(payload []byte) []byte {
	var buffer bytes.Buffer
	msg := Message {
		sessionId: 0x0,
		securityFlags: 0,
		messageCounter: 1000,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
		prot: ProtocolMessage{
			exchangeFlags: 5,
			opcode: 0x30, //sigma1
			exchangeId: 0xba3f,
			protocolId: 0x00,
		},
	}
	msg.encode(&buffer)

	buffer.Write(payload)
	return buffer.Bytes()
}

func genSigma3Req(payload []byte) []byte {
	var buffer bytes.Buffer
	msg := Message {
		sessionId: 0x0,
		securityFlags: 0,
		messageCounter: 1001,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
		prot: ProtocolMessage{
			exchangeFlags: 5,
			opcode: 0x32, //sigma1
			exchangeId: 0xba3f,
			protocolId: 0x00,
		},
	}
	msg.encode(&buffer)

	buffer.Write(payload)
	return buffer.Bytes()
}