package main

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"gomat/ca"
	"gomat/tlvdec"
	"log"
	"net"

	"github.com/spf13/cobra"
)


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


type SecureChannel struct {
	udp *Channel
	encrypt_key []byte
	decrypt_key []byte
	remote_node []byte
	local_node []byte
	counter uint32
	session int
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
			out.payload = tlvdata[:n]
		}
	} else {
		out.proto.decode(decode_buffer)
		if len(decode_buffer.Bytes()) > 0 {
			tlvdata := make([]byte, decode_buffer.Len())
			n, _ := decode_buffer.Read(tlvdata)
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

func (sc *SecureChannel)send(session uint16, data []byte) {
	sc.counter = sc.counter + 1
	var buffer bytes.Buffer
	msg := Message {
		sessionId: session,
		securityFlags: 0,
		messageCounter: sc.counter,
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

		nonce := make_nonce3(sc.counter, sc.local_node)

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


func do_spake2p(pin int, udp *Channel) SecureChannel {
	secure_channel := SecureChannel {
		udp: udp,
	}

	pbkdf_request := PBKDFParamRequest()
	secure_channel.send(0, pbkdf_request)

	pbkdf_responseS := secure_channel.receive()
	pbkdf_response_salt := pbkdf_responseS.tlv.GetOctetStringRec([]int{4,2})
	pbkdf_response_iterations := pbkdf_responseS.tlv.GetIntRec([]int{4,1})
	pbkdf_response_session := pbkdf_responseS.tlv.GetIntRec([]int{3})


	ack := AckWS(pbkdf_responseS.msg.messageCounter)
	secure_channel.send(0, ack)

	sctx := newSpaceCtx()
	sctx.gen_w(pin, pbkdf_response_salt, int(pbkdf_response_iterations))
	sctx.gen_random_X()
	sctx.calc_X()

	pake1 := Pake1ParamRequest(sctx.X.as_bytes())
	secure_channel.send(0, pake1)

	pake2s := secure_channel.receive()
	pake2s.tlv.Dump(1)
	pake2_pb := pake2s.tlv.GetOctetStringRec([]int{1})

	ack = AckWS(pake2s.msg.messageCounter)
	secure_channel.send(0, ack)

	sctx.Y.from_bytes(pake2_pb)
	sctx.calc_ZV()
	ttseed := []byte("CHIP PAKE V1 Commissioning")
	ttseed = append(ttseed, pbkdf_request[6:]...) // 6 is size of proto header
	ttseed = append(ttseed, pbkdf_responseS.payload...)
	sctx.calc_hash(ttseed)

	pake3 := Pake3ParamRequest(sctx.cA)
	secure_channel.send(0, pake3)


	status_report := secure_channel.receive()
	ack = AckWS(status_report.msg.messageCounter)
	secure_channel.send(0, ack)

	secure_channel = SecureChannel {
		udp: udp,
		decrypt_key: sctx.decrypt_key,
		encrypt_key: sctx.encrypt_key,
		remote_node: []byte{0,0,0,0,0,0,0,0},
		local_node: []byte{0,0,0,0,0,0,0,0},
		session: int(pbkdf_response_session),
	}

	return secure_channel
}

func flow() {

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

	secure_channel = do_spake2p(123456, &channel)
	pbkdf_response_session := secure_channel.session

	// send csr request
	bb := make([]byte, 32)
	rand.Read(bb)
	var tlv TLVBuffer
	tlv.writeOctetString(0, bb)
	to_send := invokeCommand2(0, 0x3e, 4, tlv.data.Bytes())
	secure_channel.send(uint16(pbkdf_response_session), to_send)


	secure_channel.receive()//ack

	ds := secure_channel.receive()
	ack := Ack3(ds.msg.messageCounter)
	secure_channel.send(uint16(pbkdf_response_session), ack)



	nocsr := ds.tlv.GetOctetStringRec([]int{1,0,0,1,0})
	tlv2 := tlvdec.Decode(nocsr)
	csr := tlv2.GetOctetStringRec([]int{1})
	csrp, err := x509.ParseCertificateRequest(csr)



	//AddTrustedRootCertificate
	var tlv4 TLVBuffer
	tlv4.writeOctetString(0, CAMatterCert2())
	to_send = invokeCommand2(0, 0x3e, 0xb, tlv4.data.Bytes())

	secure_channel.send(uint16(pbkdf_response_session), to_send)


	rec_decoded := secure_channel.receive()
	rec_decoded.msg.dump()
	rec_decoded.proto.dump()


	ds = secure_channel.receive()
	ack = Ack3(ds.msg.messageCounter)
	secure_channel.send(uint16(pbkdf_response_session), ack)


	noc_x509 := sign_cert(csrp, 2, "user")
	noc_matter := MatterCert2(noc_x509)
	//AddNOC
	var tlv5 TLVBuffer
	tlv5.writeOctetString(0, noc_matter)
	tlv5.writeOctetString(2, []byte{0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf}) //ipk
	tlv5.writeUInt(3, TYPE_UINT_2, 9)  // admin subject !
	tlv5.writeUInt(4, TYPE_UINT_2, 101)
	to_send = invokeCommand2(0, 0x3e, 0x6, tlv5.data.Bytes())

	secure_channel.send(uint16(pbkdf_response_session), to_send)


	secure_channel.receive() // ack
	ds = secure_channel.receive()
	ack = Ack3(ds.msg.messageCounter)
	secure_channel.send(uint16(pbkdf_response_session), ack)



	secure_channel.decrypt_key = []byte{}
	secure_channel.encrypt_key = []byte{}
	//-------- sigma1
	controller_privkey, _ := ecdh.P256().GenerateKey(rand.Reader)
	sigma1_payload := genSigma1(controller_privkey)
	sigma1 := genSigma1Req2(sigma1_payload)
	secure_channel.send(0, sigma1)


	sigma2dec := secure_channel.receive()
	ack = AckWS2(sigma2dec.msg.messageCounter)
	secure_channel.send(0, ack)

	to_send, sigma2responder_session, keypack := sigma3(controller_privkey, sigma2dec, sigma1_payload)
	secure_channel.send(0, to_send)

	respx := secure_channel.receive()

	ack = AckWS2(respx.msg.messageCounter)
	secure_channel.send(0, ack)

	i2rkey := keypack[:16]
	r2ikey := keypack[16:32]
	secure_channel.decrypt_key = r2ikey
	secure_channel.encrypt_key = i2rkey
	secure_channel.remote_node = []byte{2,0,0,0,0,0,0,0}
	secure_channel.local_node = []byte{9,0,0,0,0,0,0,0}
	//log.Println(hex.EncodeToString(keypack))


	//commissioning complete
	to_send = invokeCommand2(0, 0x30, 4, []byte{})
	secure_channel.send(uint16(sigma2responder_session), to_send)


	respx = secure_channel.receive()
	ack = Ack3(respx.msg.messageCounter)
	secure_channel.send(uint16(sigma2responder_session), ack)


	//LIGHT ON!!!!!!!!!!!!!!!!!!!!!
	// cluster=6 on/off - command 1=on
	to_send = invokeCommand2(1, 6, 1, []byte{})
	secure_channel.send(uint16(sigma2responder_session), to_send)

	light_resp := secure_channel.receive()
	light_resp.tlv.Dump(0)

	ack = Ack3(light_resp.msg.messageCounter)
	secure_channel.send(uint16(sigma2responder_session), ack)

	//r1 := invokeRead(0, 0x28, 1)
	//secure_channel.send(uint16(sigma2responder_session), r1)
	//resp := secure_channel.receive()
	//resp.tlv.Dump(0)

	r1 := invokeRead(0, 0x1d, 0)
	secure_channel.send(uint16(sigma2responder_session), r1)
	resp := secure_channel.receive()
	resp.tlv.Dump(0)
	ack = Ack3(resp.msg.messageCounter)
	secure_channel.send(uint16(sigma2responder_session), ack)
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
