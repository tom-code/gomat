package main

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)


type SigmaContext struct {
	session_privkey *ecdh.PrivateKey
	session int
	controller_key *ecdsa.PrivateKey
	controller_matter_certificate []byte

	i2rkey []byte
	r2ikey []byte

	sigma2dec DecodedGeneric
	sigma1payload []byte
}

func (sc *SigmaContext)genSigma1(fabric *Fabric) {
	var tlv TLVBuffer
	tlv.writeAnonStruct()
	
	initiatorRandom := make([]byte, 32)
	rand.Read(initiatorRandom)
	tlv.writeOctetString(1, initiatorRandom)

	sessionId := 222
	tlv.writeUInt(2, TYPE_UINT_2, uint64(sessionId))

	var destination_message bytes.Buffer
	destination_message.Write(initiatorRandom)
	//cacert := ca.LoadCert("ca-cert.pem")
	cacert := fabric.certificateManager.ca_certificate
	capub := cacert.PublicKey.(*ecdsa.PublicKey)
	capublic_key := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)

	destination_message.Write(capublic_key)

	var fabric_id uint64
	fabric_id = fabric.id
	binary.Write(&destination_message, binary.LittleEndian, fabric_id)

	var node uint64
	node = 2
	binary.Write(&destination_message, binary.LittleEndian, node)

	key := fabric.make_ipk()

	//log.Printf("dest id %s\n", hex.EncodeToString(destination_message.Bytes()))

	mac := hmac.New(sha256.New, key)
	mac.Write(destination_message.Bytes())
	destinationIdentifier := mac.Sum(nil)
	//log.Printf("hmaec %s", hex.EncodeToString(destinationIdentifier))

	tlv.writeOctetString(3, destinationIdentifier)


	tlv.writeOctetString(4, sc.session_privkey.PublicKey().Bytes())
	tlv.writeAnonStructEnd()
	//return tlv.data.Bytes()
	sc.sigma1payload = tlv.data.Bytes()
}


func genSigma1Req2(payload []byte) []byte {
	var buffer bytes.Buffer
	prot:= ProtocolMessage{
			exchangeFlags: 5,
			opcode: 0x30, //sigma1
			exchangeId: 0xba3f,
			protocolId: 0x00,
	}
	prot.encode(&buffer)

	buffer.Write(payload)
	return buffer.Bytes()
}

func genSigma3Req2(payload []byte) []byte {
	var buffer bytes.Buffer
	prot:= ProtocolMessage{
		exchangeFlags: 5,
		opcode: 0x32, //sigma1
		exchangeId: 0xba3f,
		protocolId: 0x00,	}

	prot.encode(&buffer)

	buffer.Write(payload)
	return buffer.Bytes()
}

func (sc *SigmaContext)sigma3(fabric *Fabric) []byte {

	var tlv_s3tbs TLVBuffer
	tlv_s3tbs.writeAnonStruct()
	tlv_s3tbs.writeOctetString(1, sc.controller_matter_certificate)
	tlv_s3tbs.writeOctetString(3, sc.session_privkey.PublicKey().Bytes())
	responder_public := sc.sigma2dec.tlv.GetOctetStringRec([]int{3})
	sigma2responder_session, err := sc.sigma2dec.tlv.GetIntRec([]int{2})
	if err != nil {
		panic("can't get sigma2responder_session")
	}
	tlv_s3tbs.writeOctetString(4, responder_public)
	tlv_s3tbs.writeAnonStructEnd()
	//log.Printf("responder public %s\n", hex.EncodeToString(responder_public))
	s2 := sha256.New()
	s2.Write(tlv_s3tbs.data.Bytes())
	tlv_s3tbs_hash := s2.Sum(nil)
	sr, ss, err := ecdsa.Sign(rand.Reader, sc.controller_key, tlv_s3tbs_hash)
	if err != nil {
		panic(err)
	}
	tlv_s3tbs_out :=  append(sr.Bytes(), ss.Bytes()...)

	var tlv_s3tbe TLVBuffer
	tlv_s3tbe.writeAnonStruct()
	tlv_s3tbe.writeOctetString(1, sc.controller_matter_certificate)
	tlv_s3tbe.writeOctetString(3, tlv_s3tbs_out)
	tlv_s3tbe.writeAnonStructEnd()

	pub, err := ecdh.P256().NewPublicKey(responder_public)
	if err != nil {
		panic(err)
	}
	shared_secret, err := sc.session_privkey.ECDH(pub)
	if err != nil {
		panic(err)
	}
	s3k_th := sc.sigma1payload
	s3k_th = append(s3k_th, sc.sigma2dec.payload...)
	s2 = sha256.New()
	s2.Write(s3k_th)
	transcript_hash := s2.Sum(nil)
	s3_salt := fabric.make_ipk()
	s3_salt = append(s3_salt, transcript_hash...)
	s3kengine := hkdf.New(sha256.New, shared_secret, s3_salt, []byte("Sigma3"))
	s3k := make([]byte, 16)
	if _, err := io.ReadFull(s3kengine, s3k); err != nil {
		panic(err)
	}

	c, err := aes.NewCipher(s3k)
	if err != nil {
		panic(err)
	}
	nonce := []byte("NCASE_Sigma3N")
	ccm, err := NewCCMWithNonceAndTagSizes(c, len(nonce), 16)
	if err != nil {
		panic(err)
	}
	CipherText := ccm.Seal(nil, nonce, tlv_s3tbe.data.Bytes(), []byte{})

	var tlv_s3 TLVBuffer
	tlv_s3.writeAnonStruct()
	tlv_s3.writeOctetString(1, CipherText)
	tlv_s3.writeAnonStructEnd()


	to_send := genSigma3Req2(tlv_s3.data.Bytes())

	// prepare session keys
	ses_key_transcript := s3k_th
	ses_key_transcript = append(ses_key_transcript, tlv_s3.data.Bytes()...)
	s2 = sha256.New()
	s2.Write(ses_key_transcript)
	transcript_hash = s2.Sum(nil)
	salt := fabric.make_ipk()
	salt = append(salt, transcript_hash...)

	keypackengine := hkdf.New(sha256.New, shared_secret, salt, []byte("SessionKeys"))
	keypack := make([]byte, 16*3)
	if _, err := io.ReadFull(keypackengine, keypack); err != nil {
		panic(err)
	}
	sc.session = int(sigma2responder_session)

	sc.i2rkey = keypack[:16]
	sc.r2ikey = keypack[16:32]

	return to_send
}