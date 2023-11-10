package gomat

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"

	"github.com/tom-code/gomat/ccm"
	"github.com/tom-code/gomat/mattertlv"
)

type sigmaContext struct {
	session_privkey               *ecdh.PrivateKey
	session                       int
	controller_key                *ecdsa.PrivateKey
	controller_matter_certificate []byte

	i2rkey []byte
	r2ikey []byte

	sigma2dec     DecodedGeneric
	sigma1payload []byte
	exchange      uint16
}

func (sc *sigmaContext) genSigma1(fabric *Fabric, device_id uint64) {
	var tlvx mattertlv.TLVBuffer
	tlvx.WriteAnonStruct()

	initiatorRandom := make([]byte, 32)
	rand.Read(initiatorRandom)
	tlvx.WriteOctetString(1, initiatorRandom)

	sessionId := 222
	tlvx.WriteUInt(2, mattertlv.TYPE_UINT_2, uint64(sessionId))

	var destination_message bytes.Buffer
	destination_message.Write(initiatorRandom)
	//cacert := ca.LoadCert("ca-cert.pem")
	cacert := fabric.CertificateManager.GetCaCertificate()
	capub := cacert.PublicKey.(*ecdsa.PublicKey)
	capublic_key := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)

	destination_message.Write(capublic_key)

	var fabric_id uint64
	fabric_id = fabric.id
	binary.Write(&destination_message, binary.LittleEndian, fabric_id)

	var node uint64
	node = device_id
	binary.Write(&destination_message, binary.LittleEndian, node)

	key := fabric.make_ipk()

	destinationIdentifier := hmac_sha256_enc(destination_message.Bytes(), key)

	tlvx.WriteOctetString(3, destinationIdentifier)

	tlvx.WriteOctetString(4, sc.session_privkey.PublicKey().Bytes())
	tlvx.WriteAnonStructEnd()
	sc.sigma1payload = tlvx.Bytes()
}

func genSigma1Req2(payload []byte, exchange uint16) []byte {
	var buffer bytes.Buffer
	prot := ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode:        0x30, //sigma1
		ExchangeId:    exchange,
		ProtocolId:    0x00,
	}
	prot.Encode(&buffer)

	buffer.Write(payload)
	return buffer.Bytes()
}

func genSigma3Req2(payload []byte, exchange uint16) []byte {
	var buffer bytes.Buffer
	prot := ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode:        0x32, //sigma1
		ExchangeId:    exchange,
		ProtocolId:    0x00}

	prot.Encode(&buffer)

	buffer.Write(payload)
	return buffer.Bytes()
}

func (sc *sigmaContext) sigma3(fabric *Fabric) ([]byte, error) {
	var tlv_s3tbs mattertlv.TLVBuffer
	tlv_s3tbs.WriteAnonStruct()
	tlv_s3tbs.WriteOctetString(1, sc.controller_matter_certificate)
	tlv_s3tbs.WriteOctetString(3, sc.session_privkey.PublicKey().Bytes())
	responder_public := sc.sigma2dec.Tlv.GetOctetStringRec([]int{3})
	sigma2responder_session, err := sc.sigma2dec.Tlv.GetIntRec([]int{2})
	if err != nil {
		return []byte{}, err
	}
	tlv_s3tbs.WriteOctetString(4, responder_public)
	tlv_s3tbs.WriteAnonStructEnd()
	//log.Printf("responder public %s\n", hex.EncodeToString(responder_public))

	tlv_s3tbs_hash := sha256_enc(tlv_s3tbs.Bytes())
	sr, ss, err := ecdsa.Sign(rand.Reader, sc.controller_key, tlv_s3tbs_hash)
	if err != nil {
		return []byte{}, err
	}
	tlv_s3tbs_out := append(sr.Bytes(), ss.Bytes()...)

	var tlv_s3tbe mattertlv.TLVBuffer
	tlv_s3tbe.WriteAnonStruct()
	tlv_s3tbe.WriteOctetString(1, sc.controller_matter_certificate)
	tlv_s3tbe.WriteOctetString(3, tlv_s3tbs_out)
	tlv_s3tbe.WriteAnonStructEnd()

	pub, err := ecdh.P256().NewPublicKey(responder_public)
	if err != nil {
		return []byte{}, err
	}
	shared_secret, err := sc.session_privkey.ECDH(pub)
	if err != nil {
		return []byte{}, err
	}
	s3k_th := sc.sigma1payload
	s3k_th = append(s3k_th, sc.sigma2dec.payload...)

	transcript_hash := sha256_enc(s3k_th)
	s3_salt := fabric.make_ipk()
	s3_salt = append(s3_salt, transcript_hash...)

	s3k := hkdf_sha256(shared_secret, s3_salt, []byte("Sigma3"), 16)

	c, err := aes.NewCipher(s3k)
	if err != nil {
		return []byte{}, err
	}
	nonce := []byte("NCASE_Sigma3N")
	ccm, err := ccm.NewCCM(c, 16, len(nonce))
	if err != nil {
		return []byte{}, err
	}
	CipherText := ccm.Seal(nil, nonce, tlv_s3tbe.Bytes(), []byte{})

	var tlv_s3 mattertlv.TLVBuffer
	tlv_s3.WriteAnonStruct()
	tlv_s3.WriteOctetString(1, CipherText)
	tlv_s3.WriteAnonStructEnd()

	to_send := genSigma3Req2(tlv_s3.Bytes(), sc.exchange)

	// prepare session keys
	ses_key_transcript := s3k_th
	ses_key_transcript = append(ses_key_transcript, tlv_s3.Bytes()...)
	transcript_hash = sha256_enc(ses_key_transcript)
	salt := fabric.make_ipk()
	salt = append(salt, transcript_hash...)

	keypack := hkdf_sha256(shared_secret, salt, []byte("SessionKeys"), 16*3)
	sc.session = int(sigma2responder_session)

	sc.i2rkey = keypack[:16]
	sc.r2ikey = keypack[16:32]

	return to_send, nil
}
