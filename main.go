package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"
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


	b := "c4f68604b151d21f2afac9e61a745ade93fde7dce1c6615de543f230bd62dd85"
	bb, _ := hex.DecodeString(b)
	to_send := invokeCommand(0, 0x3e, 4, bb)

	var add bytes.Buffer
	add.WriteByte(4)
	//add.WriteByte(pbkdf_response.PBKDFParamResponse.responderSession)
	log.Printf("responder session %x\n", pbkdf_response_decoded.PBKDFParamResponse.responderSession)
	binary.Write(&add, binary.LittleEndian, uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession))
	add.WriteByte(0)
	var cnt uint32
	cnt = uint32(channel.get_counter())
	nonce := make_nonce(cnt)
	binary.Write(&add, binary.LittleEndian, cnt)
	add.Write([]byte{1,2,3,4,5,6,7,8})
	sec := Secured(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, to_send, sctx.encrypt_key, nonce, add.Bytes())
	channel.send(sec)
}

func main_old() {

	test3()
	/*w0, w1 := genw0w1_tmp(pinToPasscode(1000), []byte{1,2,3}, 1000, 80)
	log.Println(hex.EncodeToString(w0))
	log.Println(hex.EncodeToString(w1))

	test1()
	test2()*/

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


	udpr, err := net.ListenPacket("udp", ":55555")
	if err != nil {
		panic(err)
	}
	req := PBKDFParamRequest()
	p_req := req
	addr := net.UDPAddr {
		IP: device.addrs[1],
		Port: 5540,
	}
	log.Println(addr)
	udpr.WriteTo(req, &addr)
	buf := make([]byte, 1024)
	n, addrx, errx := udpr.ReadFrom(buf)
	if errx != nil {
		panic(errx)
	}
	log.Println(addrx)
	log.Println(n)
	respbin := buf[:n]
	presp := make([]byte, len(respbin))
	copy(presp, respbin)
	log.Println(respbin)
	respstr := hex.EncodeToString(respbin)
	log.Println(respstr)
	resp := decode(respbin)
	pbkdf_response := resp
	ctx := newSpaceCtx()
	ctx.gen_w(123456, resp.PBKDFParamResponse.salt, resp.PBKDFParamResponse.iterations)
	ctx.gen_random_X()
	//ctx.gen_random_Y()
	ctx.calc_X()

	ack := Ack(2, resp.messageCounter)
	udpr.WriteTo(ack, &addr)

	time.Sleep(1*time.Second)

	pake1 := Pake1ParamRequest(ctx.X.as_bytes(), 3)
	udpr.WriteTo(pake1, &addr)

	n, addrx, errx = udpr.ReadFrom(buf)
	if errx != nil {
		panic(errx)
	}
	resp = decode(respbin)
	respbin = buf[:n]
	log.Println(resp)

	ack = Ack(4, resp.messageCounter)
	udpr.WriteTo(ack, &addr)

	ctx.Y.from_bytes(resp.PAKE2ParamResponse.pb)
	ctx.calc_ZV()
	ttseed := []byte("CHIP PAKE V1 Commissioning")
	ttseed = append(ttseed, p_req[22:]...)
	ttseed = append(ttseed, presp[26:]...)
	log.Printf("context len %d", len(ttseed))
	log.Printf("context  %s", hex.EncodeToString(ttseed))
	log.Println(hex.EncodeToString(p_req[22:]))
	log.Println(hex.EncodeToString(presp[26:]))
	ctx.calc_hash(ttseed)
	log.Printf("remote hast: %s", hex.EncodeToString(resp.PAKE2ParamResponse.cb))

	pake3 := Pake3ParamRequest(ctx.cA, 5)
	udpr.WriteTo(pake3, &addr)

	n, addrx, errx = udpr.ReadFrom(buf)
	if errx != nil {
		panic(errx)
	}
	respbin = buf[:n]
	resp = decode(respbin)
	resp.StatusReport.dump()
	ack = Ack(6, resp.messageCounter)
	udpr.WriteTo(ack, &addr)



	nonce := make_nonce(7)
	log.Printf("nonce %s\n", hex.EncodeToString(nonce))

	//to_send, _ := hex.DecodeString("05025e630100153600172403312504fcff181724020024033024040018172402002403302404011817240200240330240402181724020024033024040318172402002403282404021817240200240328240404181724033124040318172402002403381818280324ff0a18")

	b := "c4f68604b151d21f2afac9e61a745ade93fde7dce1c6615de543f230bd62dd85"
	bb, _ := hex.DecodeString(b)
	to_send := invokeCommand(0, 0x3e, 4, bb)

	//sec := Secured(uint16(pbkdf_response.PBKDFParamResponse.responderSession), 7, to_send)
	var add bytes.Buffer
	add.WriteByte(4)
	//add.WriteByte(pbkdf_response.PBKDFParamResponse.responderSession)
	log.Printf("responder session %x\n", pbkdf_response.PBKDFParamResponse.responderSession)
	binary.Write(&add, binary.LittleEndian, uint16(pbkdf_response.PBKDFParamResponse.responderSession))
	add.WriteByte(0)
	var cnt uint32
	cnt = 7
	binary.Write(&add, binary.LittleEndian, cnt)
	add.Write([]byte{1,2,3,4,5,6,7,8})
	sec := Secured(uint16(pbkdf_response.PBKDFParamResponse.responderSession), cnt, to_send, ctx.encrypt_key, nonce, add.Bytes())
	//seco := []byte{0,0,0,0,0,0,0,0}
	//seco = append(seco, sec...)
	udpr.WriteTo(sec, &addr)

	n, addrx, errx = udpr.ReadFrom(buf)
	if errx != nil {
		panic(errx)
	}
	respbin = buf[:n]
	log.Printf("received %s\n", hex.EncodeToString(respbin))

	n, addrx, errx = udpr.ReadFrom(buf)
	if errx != nil {
		panic(errx)
	}
	respbin = buf[:n]
	log.Printf("received %s\n", hex.EncodeToString(respbin))

	time.Sleep(time.Second*1)


	// create secure session
	// https://github.com/project-chip/matter.js/blob/main/packages/matter.js/src/session/SecureSession.ts#L33
	// https://github.com/project-chip/matter.js/blob/main/packages/matter.js/src/session/pase/PaseClient.ts#L57
	/*
	devices, err := discover()
	if err != nil {
		panic(err)
	}
	log.Printf("%v\n", devices)
	for _, d := range devices {
		d.Dump()
	}*/
}