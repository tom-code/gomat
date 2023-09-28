package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
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
	to_send := invokeCommand(0, 0x3e, 4, bb)




	log.Printf("responder session %x\n", pbkdf_response_decoded.PBKDFParamResponse.responderSession)
	var cnt uint32
	cnt = uint32(channel.get_counter())
	nonce := make_nonce(cnt)
	sec := Secured(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, to_send, sctx.encrypt_key, nonce)
	channel.send(sec)

	channel.receive() // ack
	csr_response, _ := channel.receive()
	decodeSecured(csr_response, sctx.decrypt_key)
}
