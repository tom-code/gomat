package gomat

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"log"
	randm "math/rand"
	"net"

	"github.com/tom-code/gomat/tlvdec"
	"github.com/tom-code/gomat/tlvenc"
)



func Spake2pExchange(pin int, udp *Channel) SecureChannel {
	exchange := uint16(randm.Intn(0xffff))
	secure_channel := SecureChannel {
		Udp: udp,
		session: 0,
	}

	pbkdf_request := PBKDFParamRequest(exchange)
	secure_channel.Send(pbkdf_request)

	pbkdf_responseS := secure_channel.Receive()
	if pbkdf_responseS.proto.opcode != SEC_CHAN_OPCODE_PBKDF_RESP {
		panic("SEC_CHAN_OPCODE_PBKDF_RESP not received")
	}
	pbkdf_response_salt := pbkdf_responseS.Tlv.GetOctetStringRec([]int{4,2})
	pbkdf_response_iterations, err := pbkdf_responseS.Tlv.GetIntRec([]int{4,1})
	if err != nil {
		panic("can't get pbkdf_response_iterations")
	}
	pbkdf_response_session, err := pbkdf_responseS.Tlv.GetIntRec([]int{3})
	if err != nil {
		panic("can't get pbkdf_response_session")
	}


	sctx := newSpaceCtx()
	sctx.gen_w(pin, pbkdf_response_salt, int(pbkdf_response_iterations))
	sctx.gen_random_X()
	sctx.calc_X()

	pake1 := Pake1ParamRequest(exchange, sctx.X.as_bytes())
	secure_channel.Send(pake1)

	pake2s := secure_channel.Receive()
	if pake2s.proto.opcode != SEC_CHAN_OPCODE_PAKE2 {
		panic("SEC_CHAN_OPCODE_PAKE2 not received")
	}
	//pake2s.tlv.Dump(1)
	pake2_pb := pake2s.Tlv.GetOctetStringRec([]int{1})


	sctx.Y.from_bytes(pake2_pb)
	sctx.calc_ZV()
	ttseed := []byte("CHIP PAKE V1 Commissioning")
	ttseed = append(ttseed, pbkdf_request[6:]...) // 6 is size of proto header
	ttseed = append(ttseed, pbkdf_responseS.payload...)
	sctx.calc_hash(ttseed)

	pake3 := Pake3ParamRequest(exchange, sctx.cA)
	secure_channel.Send(pake3)


	/*status_report :=*/ secure_channel.Receive()

	secure_channel = SecureChannel {
		Udp: udp,
		decrypt_key: sctx.decrypt_key,
		encrypt_key: sctx.encrypt_key,
		remote_node: []byte{0,0,0,0,0,0,0,0},
		local_node: []byte{0,0,0,0,0,0,0,0},
		session: int(pbkdf_response_session),
	}

	return secure_channel
}

func SigmaExchange(fabric *Fabric, controller_id uint64, device_id uint64, secure_channel SecureChannel) SecureChannel {

	controller_privkey, _ := ecdh.P256().GenerateKey(rand.Reader)
	sigma_context := SigmaContext {
		session_privkey: controller_privkey,
		exchange: uint16(randm.Intn(0xffff)),
	}
	sigma_context.genSigma1(fabric, device_id)
	sigma1 := genSigma1Req2(sigma_context.sigma1payload, sigma_context.exchange)
	secure_channel.Send(sigma1)


	sigma_context.sigma2dec = secure_channel.Receive()
	if sigma_context.sigma2dec.proto.opcode != 0x31 {
		panic("sigma2 not received")
	}

	sigma_context.controller_key = fabric.CertificateManager.GetPrivkey(controller_id)
	sigma_context.controller_matter_certificate = MatterCert2(fabric, fabric.CertificateManager.GetCertificate(controller_id))

	to_send := sigma_context.sigma3(fabric)
	secure_channel.Send(to_send)

	/*respx :=*/ secure_channel.Receive()

	secure_channel.decrypt_key = sigma_context.r2ikey
	secure_channel.encrypt_key = sigma_context.i2rkey
	secure_channel.remote_node = id_to_bytes(device_id)
	secure_channel.local_node = id_to_bytes(controller_id)
	secure_channel.session = sigma_context.session
	return secure_channel
}

func Commision(fabric *Fabric, device_ip net.IP, pin int, controller_id, device_id uint64) {

	channel := NewChannel(device_ip, 5540, 55555)
	secure_channel := SecureChannel {
		Udp: &channel,
	}

	secure_channel = Spake2pExchange(pin, &channel)

	// send csr request
	var tlv tlvenc.TLVBuffer
	tlv.WriteOctetString(0, create_random_bytes(32))
	to_send := InvokeCommand(0, 0x3e, 4, tlv.Bytes())
	secure_channel.Send(to_send)

	csr_resp := secure_channel.Receive()

	nocsr := csr_resp.Tlv.GetOctetStringRec([]int{1,0,0,1,0})
	tlv2 := tlvdec.Decode(nocsr)
	csr := tlv2.GetOctetStringRec([]int{1})
	csrp, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		panic(err)
	}

	//AddTrustedRootCertificate
	var tlv4 tlvenc.TLVBuffer
	tlv4.WriteOctetString(0, MatterCert2(fabric, fabric.CertificateManager.GetCaCertificate()))
	to_send = InvokeCommand(0, 0x3e, 0xb, tlv4.Bytes())
	secure_channel.Send(to_send)


	/*ds :=*/ secure_channel.Receive()


	//noc_x509 := sign_cert(csrp, 2, "user")
	noc_x509 := fabric.CertificateManager.SignCertificate(csrp.PublicKey.(*ecdsa.PublicKey), device_id)
	noc_matter := MatterCert2(fabric, noc_x509)
	//AddNOC
	var tlv5 tlvenc.TLVBuffer
	tlv5.WriteOctetString(0, noc_matter)
	tlv5.WriteOctetString(2, fabric.ipk) //ipk
	tlv5.WriteUInt(3, tlvenc.TYPE_UINT_2, controller_id)   // admin subject !
	tlv5.WriteUInt(4, tlvenc.TYPE_UINT_2, 101) // admin vendorid ??
	to_send = InvokeCommand(0, 0x3e, 0x6, tlv5.Bytes())

	secure_channel.Send(to_send)

	/*ds =*/ secure_channel.Receive()

	secure_channel.decrypt_key = []byte{}
	secure_channel.encrypt_key = []byte{}
	secure_channel.session = 0

	secure_channel = SigmaExchange(fabric, controller_id, device_id, secure_channel)


	//commissioning complete
	to_send = InvokeCommand(0, 0x30, 4, []byte{})
	secure_channel.Send(to_send)


	respx := secure_channel.Receive()
	commisioning_result, err := respx.Tlv.GetIntRec([]int{1, 0, 0, 1, 0})
	if err != nil {
		panic(err)
	}
	if commisioning_result == 0 {
		log.Printf("commissioning OK\n")
	} else {
		log.Printf("commissioning error: %d\n", commisioning_result)
	}
}