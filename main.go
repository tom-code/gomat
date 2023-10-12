package main

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"gomat/ca"
	"gomat/tlvdec"
	"io"
	"log"
	"net"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/hkdf"
)

func make_nonce(counter uint32) []byte{
	var n bytes.Buffer
	n.WriteByte(0)
	binary.Write(&n, binary.LittleEndian, counter)
	n.Write([]byte{0,0,0,0,0,0,0,0})
	return n.Bytes()
}
func make_nonce2(counter uint32) []byte{
	var n bytes.Buffer
	n.WriteByte(0)
	binary.Write(&n, binary.LittleEndian, counter)
	n.Write([]byte{9,0,0,0,0,0,0,0})
	return n.Bytes()
}
func make_nonce3(counter uint32, node []byte) []byte{
	var n bytes.Buffer
	n.WriteByte(0)
	binary.Write(&n, binary.LittleEndian, counter)
	n.Write(node)
	return n.Bytes()
}


type Channel struct {
	udp net.PacketConn
	remote_address net.UDPAddr
	out_counter uint32
}

func NewChannel(remote_ip net.IP, remote_port, local_port int) Channel {
	var out Channel
	out.remote_address = net.UDPAddr{
		IP : remote_ip,
		Port: remote_port,
	}
	var err error
	out.udp, err = net.ListenPacket("udp", fmt.Sprintf(":%d", local_port))
	if err != nil {
		panic(err)
	}
	out.out_counter = 1
	return out
}
func (ch *Channel)get_counter() int {
	ch.out_counter = ch.out_counter + 1
	return int(ch.out_counter)
}
func (ch *Channel)send(data []byte) {
	ch.udp.WriteTo(data, &ch.remote_address)
}
func (ch *Channel)receive() ([]byte, error) {
	buf := make([]byte, 1024)
	n, _, errx := ch.udp.ReadFrom(buf)
	if errx != nil {
		panic(errx)
	}
	return buf[:n], nil
}

/*func hex2bin(in string) []byte {
	out, _ := hex.DecodeString(in)
	return out
}

func make_sha1(in []byte) []byte {
	h := sha1.New()
	return h.Sum(in)
}*/


type SecureChannel struct {
	udp *Channel
	encrypt_key []byte
	decrypt_key []byte
	remote_node []byte
	local_node []byte
}

func (sc *SecureChannel) receive() DecodedGeneric {
	data, _ := sc.udp.receive()
	decode_buffer := bytes.NewBuffer(data)
	var out DecodedGeneric
	out.msg.decodeBase(decode_buffer)
	add := data[:len(data)-decode_buffer.Len()]
	proto := decode_buffer.Bytes()


	if len(sc.decrypt_key) > 0 {
		nonce := make_nonce3(out.msg.messageCounter, sc.remote_node)
		c, err := aes.NewCipher(sc.decrypt_key)
		if err != nil {
			panic(err)
		}
		ccm, err := NewCCMWithNonceAndTagSizes(c, len(nonce), 16)
		if err != nil {
			panic(err)
		}
		ciphertext := proto
		decbuf := []byte{}
		outx, err := ccm.Open(decbuf, nonce, ciphertext, add)
		if err != nil {
			panic(err)
		}

		decoder := bytes.NewBuffer(outx)

		out.proto.decode(decoder)
		if len(decoder.Bytes()) > 0 {
			tlvdata := make([]byte, decoder.Len())
			n, _ := decoder.Read(tlvdata)
			//out.tlv = tlvdec.Decode(decoder.Bytes())
			out.payload = tlvdata[:n]
		}
	} else {
		out.proto.decode(decode_buffer)
		if len(decode_buffer.Bytes()) > 0 {
			tlvdata := make([]byte, decode_buffer.Len())
			n, _ := decode_buffer.Read(tlvdata)
			//out.tlv = tlvdec.Decode(tlvdata[:n])
			out.payload = tlvdata[:n]
		}
	}

	// do not decode status report today
	if out.proto.protocolId == 0 {
		if out.proto.opcode == 0x40 {
			return out
		}
	}
	if len(out.payload) >0 {
		out.tlv = tlvdec.Decode(out.payload)
	}
	return out
}

func (sc *SecureChannel)send(session uint16, counter uint32, data []byte) {
	var buffer bytes.Buffer
	msg := Message {
		sessionId: session,
		securityFlags: 0,
		messageCounter: counter,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
	}
	msg.encodeBase(&buffer)
	if len(sc.encrypt_key) == 0 {
		log.Printf("-- %s\n", hex.EncodeToString(buffer.Bytes()))
		buffer.Write(data)
		log.Printf("-- %s\n", hex.EncodeToString(buffer.Bytes()))
	} else {

		header_slice := buffer.Bytes()
		add2 := make([]byte, len(header_slice))
		copy(add2, header_slice)

		nonce := make_nonce3(counter, sc.local_node)

		c, err := aes.NewCipher(sc.encrypt_key)
		if err != nil {
			panic(err)
		}
		ccm, err := NewCCMWithNonceAndTagSizes(c, len(nonce), 16)
		if err != nil {
			panic(err)
		}
		CipherText := ccm.Seal(nil, nonce, data, add2)
		buffer.Write(CipherText)
	}


	sc.udp.send(buffer.Bytes())
}


func flow() {
	//tlvdec.Test1()
	//panic("")
	var devices []Device
	var err error
	for i:=0; i<5; i++ {
		devices, err = discover("en0")
		if err != nil {
			panic(err)
		}
		if len(devices) > 0 {
			break
		}

	}
	device := devices[0]

	channel := NewChannel(device.addrs[1], 5540, 55555)
	secure_channel := SecureChannel {
		udp: &channel,
	}

	pbkdf_request := PBKDFParamRequest()
	secure_channel.send(0, 1, pbkdf_request)

	pbkdf_response, _ := channel.receive()
	pbkdf_response_decoded := decode(pbkdf_response)
	//log.Println(pbkdf_response_decoded)

	ack := AckWS(uint32(channel.get_counter()), pbkdf_response_decoded.messageCounter)
	secure_channel.send(0, 2, ack)

	sctx := newSpaceCtx()
	sctx.gen_w(123456, pbkdf_response_decoded.PBKDFParamResponse.salt, pbkdf_response_decoded.PBKDFParamResponse.iterations)
	sctx.gen_random_X()
	sctx.calc_X()

	pake1 := Pake1ParamRequest(sctx.X.as_bytes(), uint32(channel.get_counter()))
	secure_channel.send(0, 3, pake1)

	pake2, _ := channel.receive()
	//log.Printf("pake2 %s\n", hex.EncodeToString(pake2))
	pake2_decoded := decode(pake2)
	//log.Println(pake2_decoded)

	ack = AckWS(uint32(channel.get_counter()), pake2_decoded.messageCounter)
	secure_channel.send(0, 4, ack)

	sctx.Y.from_bytes(pake2_decoded.PAKE2ParamResponse.pb)
	sctx.calc_ZV()
	ttseed := []byte("CHIP PAKE V1 Commissioning")
	ttseed = append(ttseed, pbkdf_request[6:]...) // 6 is size of proto header
	ttseed = append(ttseed, pbkdf_response[26:]...)
	sctx.calc_hash(ttseed)

	pake3 := Pake3ParamRequest(sctx.cA, uint32(channel.get_counter()))
	secure_channel.send(0, 5, pake3)

	status_report, _ := channel.receive()
	status_report_decoded := decode(status_report)
	ack = AckWS(uint32(channel.get_counter()), status_report_decoded.messageCounter)
	secure_channel.send(0, 6, ack)

	secure_channel = SecureChannel {
		udp: &channel,
		decrypt_key: sctx.decrypt_key,
		encrypt_key: sctx.encrypt_key,
		remote_node: []byte{0,0,0,0,0,0,0,0},
		local_node: []byte{0,0,0,0,0,0,0,0},
	}

	// send csr request
	bb := make([]byte, 32)
	rand.Read(bb)
	var tlv TLVBuffer
	tlv.writeOctetString(0, bb)
	to_send := invokeCommand2(0, 0x3e, 4, tlv.data.Bytes())

	//log.Printf("responder session %x\n", pbkdf_response_decoded.PBKDFParamResponse.responderSession)
	var cnt uint32
	cnt = uint32(channel.get_counter())

	secure_channel.send(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, to_send)


	channel.receive() // ack

	ds := secure_channel.receive()


	ack = Ack3(ds.msg.messageCounter)
	cnt = uint32(channel.get_counter())
	secure_channel.send(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, ack)



	nocsr := ds.tlv.GetOctetStringRec([]int{1,0,0,1,0})
	tlv2 := tlvdec.Decode(nocsr)
	//tlv2.Dump(0)
	csr := tlv2.GetOctetStringRec([]int{1})
	csrp, err := x509.ParseCertificateRequest(csr)
	//log.Printf("csr %+v\n", csrp)
	//log.Println(csrp.PublicKey)


	//AddTrustedRootCertificate
	var tlv4 TLVBuffer
	tlv4.writeOctetString(0, CAMatterCert2())
	to_send = invokeCommand2(0, 0x3e, 0xb, tlv4.data.Bytes())

	cnt = uint32(channel.get_counter())
	secure_channel.send(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, to_send)


	rec_decoded := secure_channel.receive()
	rec_decoded.msg.dump()
	rec_decoded.proto.dump()


	ds = secure_channel.receive()
	//ds.tlv.Dump(0)

	ack = Ack3(ds.msg.messageCounter)
	cnt = uint32(channel.get_counter())
	secure_channel.send(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, ack)


	noc_x509 := sign_cert(csrp, 2, "user")
	noc_matter := MatterCert2(noc_x509)
	//AddNOC
	var tlv5 TLVBuffer
	tlv5.writeOctetString(0, noc_matter)
	tlv5.writeOctetString(2, []byte{0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf}) //ipk
	tlv5.writeUInt(3, TYPE_UINT_2, 9)  // admin subject !
	tlv5.writeUInt(4, TYPE_UINT_2, 101)
	to_send = invokeCommand2(0, 0x3e, 0x6, tlv5.data.Bytes())

	cnt = uint32(channel.get_counter())
	secure_channel.send(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, to_send)


	//channel.receive() // ack
	secure_channel.receive()
	ds = secure_channel.receive()
	//ds.tlv.Dump(0)

	ack = Ack3(ds.msg.messageCounter)
	cnt = uint32(channel.get_counter())
	secure_channel.send(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, ack)



	secure_channel.decrypt_key = []byte{}
	secure_channel.encrypt_key = []byte{}
	//-------- sigma1
	controller_privkey, _ := ecdh.P256().GenerateKey(rand.Reader)
	sigma1_payload := genSigma1(controller_privkey)
	sigma1 := genSigma1Req2(sigma1_payload)
	secure_channel.send(0, 1000, sigma1)


	sigma2dec := secure_channel.receive()
	//sigma2dec.tlv.Dump(0)

	ack = AckWS2(uint32(channel.get_counter()), sigma2dec.msg.messageCounter)
	secure_channel.send(0, uint32(channel.get_counter()), ack)

	//sigma3
	controller_key := ca.Generate_and_store_key_ecdsa("controller")
	controller_csr := x509.CertificateRequest {
		PublicKey: &controller_key.PublicKey,
	}
	controller_cert := sign_cert(&controller_csr, 9, "controller")
	conrtoller_cert_matter := MatterCert2(controller_cert)

	var tlv_s3tbs TLVBuffer
	tlv_s3tbs.writeAnonStruct()
	tlv_s3tbs.writeOctetString(1, conrtoller_cert_matter)
	tlv_s3tbs.writeOctetString(3, controller_privkey.PublicKey().Bytes())
	responder_public := sigma2dec.tlv.GetOctetStringRec([]int{3})
	sigma2responder_session := sigma2dec.tlv.GetIntRec([]int{2})
	tlv_s3tbs.writeOctetString(4, responder_public)
	tlv_s3tbs.writeAnonStructEnd()
	//log.Printf("responder public %s\n", hex.EncodeToString(responder_public))
	s2 := sha256.New()
	s2.Write(tlv_s3tbs.data.Bytes())
	tlv_s3tbs_hash := s2.Sum(nil)
	sr, ss, err := ecdsa.Sign(rand.Reader, controller_key, tlv_s3tbs_hash)
	if err != nil {
		panic(err)
	}
	tlv_s3tbs_out :=  append(sr.Bytes(), ss.Bytes()...)

	var tlv_s3tbe TLVBuffer
	tlv_s3tbe.writeAnonStruct()
	tlv_s3tbe.writeOctetString(1, conrtoller_cert_matter)
	tlv_s3tbe.writeOctetString(3, tlv_s3tbs_out)
	tlv_s3tbe.writeAnonStructEnd()

	pub, err := ecdh.P256().NewPublicKey(responder_public)
	if err != nil {
		panic(err)
	}
	shared_secret, err := controller_privkey.ECDH(pub)
	if err != nil {
		panic(err)
	}
	//log.Println(shared_secret)
	s3k_th := sigma1_payload
	s3k_th = append(s3k_th, sigma2dec.payload...)
	//log.Printf("transcript %s\n", hex.EncodeToString(s3k_th))
	//log.Printf("transcript_a %s\n", hex.EncodeToString(genSigma1(controller_privkey)))
	//log.Printf("transcript_b %s\n", hex.EncodeToString(sigma2dec.payload))
	s2 = sha256.New()
	s2.Write(s3k_th)
	transcript_hash := s2.Sum(nil)
	//log.Printf("transcript hash %s\n", hex.EncodeToString(transcript_hash))
	s3_salt := make_ipk()
	s3_salt = append(s3_salt, transcript_hash...)
	//log.Printf("s3 salt %s\n", hex.EncodeToString(s3_salt))
	//log.Printf("s3 shared %s\n", hex.EncodeToString(shared_secret))
	s3kengine := hkdf.New(sha256.New, shared_secret, s3_salt, []byte("Sigma3"))
	s3k := make([]byte, 16)
	if _, err := io.ReadFull(s3kengine, s3k); err != nil {
		panic(err)
	}


	//log.Printf("key %s\n", hex.EncodeToString(s3k))
	c, err := aes.NewCipher(s3k)
	if err != nil {
		panic(err)
	}
	nonce := make_nonce(cnt) // just for size
	ccm, err := NewCCMWithNonceAndTagSizes(c, len(nonce), 16)
	if err != nil {
		panic(err)
	}
	CipherText := ccm.Seal(nil, []byte("NCASE_Sigma3N"), tlv_s3tbe.data.Bytes(), []byte{})
	//log.Printf("ciphertext %s", hex.EncodeToString(CipherText))


	var tlv_s3 TLVBuffer
	tlv_s3.writeAnonStruct()
	tlv_s3.writeOctetString(1, CipherText)
	tlv_s3.writeAnonStructEnd()


	to_send = genSigma3Req2(tlv_s3.data.Bytes())
	secure_channel.send(0, 1001, to_send)
	// sigma3 sent

	// status report
	respx := secure_channel.receive()

	ack = AckWS2(uint32(channel.get_counter()), respx.msg.messageCounter)
	secure_channel.send(0, 1002, ack)


	// prepare session keys
	ses_key_transcript := s3k_th
	ses_key_transcript = append(ses_key_transcript, tlv_s3.data.Bytes()...)
	s2 = sha256.New()
	s2.Write(ses_key_transcript)
	transcript_hash = s2.Sum(nil)
	salt := make_ipk()
	salt = append(salt, transcript_hash...)

	keypackengine := hkdf.New(sha256.New, shared_secret, salt, []byte("SessionKeys"))
	keypack := make([]byte, 16*3)
	if _, err := io.ReadFull(keypackengine, keypack); err != nil {
		panic(err)
	}
	i2rkey := keypack[:16]
	r2ikey := keypack[16:32]
	secure_channel.decrypt_key = r2ikey
	secure_channel.encrypt_key = i2rkey
	secure_channel.remote_node = []byte{2,0,0,0,0,0,0,0}
	secure_channel.local_node = []byte{9,0,0,0,0,0,0,0}
	//log.Println(hex.EncodeToString(keypack))


	//commistioning complete
	to_send = invokeCommand2(0, 0x30, 4, []byte{})
	cnt = 5000
	secure_channel.send(uint16(sigma2responder_session), cnt, to_send)


	respx = secure_channel.receive()
	ack = Ack3(respx.msg.messageCounter)
	cnt = 5001
	secure_channel.send(uint16(sigma2responder_session), cnt, ack)


	//LIGHT ON!!!!!!!!!!!!!!!!!!!!!
	// cluster=6 on/off - command 1=on
	to_send = invokeCommand2(1, 6, 1, []byte{})
	//cnt = uint32(channel.get_counter())
	cnt = 5002
	secure_channel.send(uint16(sigma2responder_session), cnt, to_send)

	light_resp := secure_channel.receive()
	light_resp.tlv.Dump(0)

	ack = Ack3(light_resp.msg.messageCounter)
	cnt = 5003
	secure_channel.send(uint16(sigma2responder_session), cnt, ack)

}


func main() {
	var rootCmd = &cobra.Command{
		Use:   "mama",
		Short: "matter manager",
	}
	var flowCmd = &cobra.Command{
		Use:   "flow",
		Run: func(cmd *cobra.Command, args []string) {
		  flow()
		},
	}
	var cakeygenCmd = &cobra.Command{
		Use:   "ca-keygen",
		Run: func(cmd *cobra.Command, args []string) {
		  ca.Create_ca_cert()
		},
	}
	var testCmd = &cobra.Command{
		Use:   "test",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	rootCmd.AddCommand(flowCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(cakeygenCmd)
	rootCmd.Execute()
}
