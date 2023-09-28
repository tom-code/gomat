package main

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"gomat/tlvdec"
	"log"
	"net"
)

func make_nonce(counter uint32) []byte{
	var n bytes.Buffer
	n.WriteByte(0)
	binary.Write(&n, binary.LittleEndian, counter)
	n.Write([]byte{0,0,0,0,0,0,0,0})
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

func main() {
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

	pbkdf_request := PBKDFParamRequest()
	channel.send(pbkdf_request)

	pbkdf_response, _ := channel.receive()
	pbkdf_response_decoded := decode(pbkdf_response)
	log.Println(pbkdf_response_decoded)

	ack := Ack(uint32(channel.get_counter()), pbkdf_response_decoded.messageCounter)
	channel.send(ack)

	sctx := newSpaceCtx()
	sctx.gen_w(123456, pbkdf_response_decoded.PBKDFParamResponse.salt, pbkdf_response_decoded.PBKDFParamResponse.iterations)
	sctx.gen_random_X()
	sctx.calc_X()

	pake1 := Pake1ParamRequest(sctx.X.as_bytes(), uint32(channel.get_counter()))
	channel.send(pake1)

	pake2, _ := channel.receive()
	pake2_decoded := decode(pake2)
	log.Println(pake2_decoded)

	ack = Ack(uint32(channel.get_counter()), pake2_decoded.messageCounter)
	channel.send(ack)

	sctx.Y.from_bytes(pake2_decoded.PAKE2ParamResponse.pb)
	sctx.calc_ZV()
	ttseed := []byte("CHIP PAKE V1 Commissioning")
	ttseed = append(ttseed, pbkdf_request[22:]...)
	ttseed = append(ttseed, pbkdf_response[26:]...)
	sctx.calc_hash(ttseed)

	pake3 := Pake3ParamRequest(sctx.cA, uint32(channel.get_counter()))
	channel.send(pake3)

	status_report, _ := channel.receive()
	status_report_decoded := decode(status_report)
	status_report_decoded.StatusReport.dump()
	ack = Ack(uint32(channel.get_counter()), status_report_decoded.messageCounter)
	channel.send(ack)
	log.Printf("remote node id: %s", hex.EncodeToString(status_report_decoded.sourceNodeId))



	b := "c4f68604b151d21f2afac9e61a745ade93fde7dce1c6615de543f230bd62dd85"
	bb, _ := hex.DecodeString(b)
	var tlv TLVBuffer
	tlv.writeOctetString(0, bb)
	to_send := invokeCommand2(0, 0x3e, 4, tlv.data.Bytes())




	log.Printf("responder session %x\n", pbkdf_response_decoded.PBKDFParamResponse.responderSession)
	var cnt uint32
	cnt = uint32(channel.get_counter())
	nonce := make_nonce(cnt)
	sec := Secured(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, to_send, sctx.encrypt_key, nonce)
	channel.send(sec)

	channel.receive() // ack
	csr_response, _ := channel.receive()
	ds := decodeSecured(csr_response, sctx.decrypt_key)


	ack = Ack3(ds.msg.messageCounter)
	cnt = uint32(channel.get_counter())
	nonce = make_nonce(cnt)
	sec = Secured(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, ack, sctx.encrypt_key, nonce)
	channel.send(sec)


	nocsr := ds.tlv.GetOctetStringRec([]int{1,0,0,1,0})
	tlv2 := tlvdec.Decode(nocsr)
	tlv2.Dump(0)
	csr := tlv2.GetOctetStringRec([]int{1})
	csrp, err := x509.ParseCertificateRequest(csr)
	log.Printf("csr %+v\n", csrp)


	var tlv3 TLVBuffer
	tlv3.writeAnonStruct()
	tlv3.writeOctetString(1, []byte{1,2})
	tlv3.writeUInt(2, TYPE_UINT_1, 1)
	//tlv3.writeUInt(3, TYPE_UINT_1, 1)
	tlv3.writeList(3)
	tlv3.writeAnonStructEnd()
	tlv3.writeUInt(4, TYPE_UINT_1, 1)
	tlv3.writeUInt(5, TYPE_UINT_1, 0)
	tlv3.writeList(6)
	tlv3.writeAnonStructEnd()
	tlv3.writeUInt(7, TYPE_UINT_1, 1)
	tlv3.writeUInt(8, TYPE_UINT_1, 1)
	tlv3.writeOctetString(9, []byte{0x04, 0x9A, 0x2A, 0x21, 0x6F, 0xB3, 0x9D, 0xD6, 0xB6, 0xFA, 0x21, 0x1B, 0x83, 0x5C, 0x89, 0xE3,
		0x04, 0x9A, 0x2A, 0x21, 0x6F, 0xB3, 0x9D, 0xD6, 0xB6, 0xFA, 0x21, 0x1B, 0x83, 0x5C, 0x89, 0xE3,
		0x04, 0x9A, 0x2A, 0x21, 0x6F, 0xB3, 0x9D, 0xD6, 0xB6, 0xFA, 0x21, 0x1B, 0x83, 0x5C, 0x89, 0xE3,
		0x04, 0x9A, 0x2A, 0x21, 0x6F, 0xB3, 0x9D, 0xD6, 0xB6, 0xFA, 0x21, 0x1B, 0x83, 0x5C, 0x89, 0xE3,
		0x83})
	tlv3.writeList(10)
	tlv3.writeAnonStructEnd()
	tlv3.writeOctetString(11, []byte{1,2,3,4,5,6,7,8,9,0,
		1,2,3,4,5,6,7,8,9,0,
		1,2,3,4,5,6,7,8,9,0,
		1,2,3,4,5,6,7,8,9,0,
		1,2,3,4,5,6,7,8,9,0,
		1,2,3,4,5,6,7,8,9,0,
		1,2,3,4,
	})
	tlv3.writeAnonStructEnd()
	//tt := []byte {0x15, 0x30, 0x01, 0x01, 0x01, 0x24, 0x02, 0x01, 0x37, 0x03, 0x24, 0x14, 0x01, 0x18, 0x26, 0x04, 0x80, 0x22, 0x81, 0x27, 0x26, 0x05, 0x80, 0x25, 0x4d, 0x3a, 0x37, 0x06, 0x24, 0x14, 0x01, 0x18, 0x24, 0x07, 0x01, 0x24, 0x08, 0x01, 0x30, 0x09, 0x41, 0x04, 0x6f, 0xc3, 0x58, 0x61, 0xa7, 0x5f, 0x0b, 0x0d, 0x9d, 0x91, 0x20, 0x09, 0xcb, 0xec, 0x15, 0x67, 0x6f, 0x24, 0x67, 0x8a, 0xee, 0xab, 0x3d, 0xcb, 0x18, 0x9c, 0x3e, 0x02, 0x15, 0x00, 0x95, 0x2c, 0x19, 0x9d, 0xff, 0x86, 0x80, 0xbf, 0x0d, 0x3a, 0x4e, 0xe7, 0xc9, 0xf6, 0x00, 0x48, 0x13, 0x5f, 0xa2, 0x10, 0xf2, 0xa4, 0xd6, 0x08, 0x89, 0xed, 0x2e, 0x6c, 0xa1, 0x21, 0x66, 0xdc, 0x90, 0x4e, 0x37, 0x0a, 0x35, 0x01, 0x29, 0x01, 0x18, 0x24, 0x02, 0x60, 0x30, 0x04, 0x14, 0xf2, 0x46, 0x2b, 0x7c, 0x9c, 0x03, 0x3a, 0x9e, 0x0a, 0xec, 0xd9, 0xa1, 0x1a, 0x33, 0x80, 0x17, 0xde, 0xe9, 0x7b, 0x69, 0x30, 0x05, 0x14, 0xf2, 0x46, 0x2b, 0x7c, 0x9c, 0x03, 0x3a, 0x9e, 0x0a, 0xec, 0xd9, 0xa1, 0x1a, 0x33, 0x80, 0x17, 0xde, 0xe9, 0x7b, 0x69, 0x18, 0x30, 0x0b, 0x40, 0x4e, 0x31, 0x3f, 0xca, 0xea, 0x8b, 0x53, 0x1b, 0x24, 0xf4, 0x4f, 0xf1, 0x45, 0x13, 0x68, 0xee, 0xa2, 0x01, 0x8c, 0x89, 0xf7, 0x87, 0xf3, 0x9c, 0x0a, 0x52, 0xb8, 0x5b, 0x08, 0x09, 0x2f, 0xd4, 0x75, 0xc2, 0x85, 0xb9, 0x99, 0x33, 0xca, 0xaa, 0x30, 0xe1, 0x06, 0xe4, 0x3b, 0xd1, 0x29, 0xa9, 0xc6, 0x57, 0x98, 0xa1, 0xba, 0x5c, 0x06, 0x68, 0x0e, 0x42, 0xf3, 0x10, 0x4d, 0xd9, 0x33, 0x6e, 0x18}
	var tlv4 TLVBuffer
	tlv4.writeOctetString(0, tlv3.data.Bytes())
	to_send = invokeCommand2(0, 0x3e, 0xb, tlv4.data.Bytes())
	//to_send = invokeCommand2(0, 0x3e, 0xb, tlv3.data.Bytes())

	cnt = uint32(channel.get_counter())
	nonce = make_nonce(cnt)
	sec = Secured(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, to_send, sctx.encrypt_key, nonce)
	channel.send(sec)
}
