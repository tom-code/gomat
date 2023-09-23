package main

import (
	"encoding/hex"
	"log"
	"net"
	"time"
)

func main() {

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

	ctx := newSpaceCtx()
	ctx.gen_w(123456, resp.PBKDFParamResponse.salt, resp.PBKDFParamResponse.iterations)
	ctx.gen_random_X()
	//ctx.gen_random_Y()
	ctx.calc_X()

	ack := Ack(2, resp.messageCounter)
	udpr.WriteTo(ack, &addr)

	time.Sleep(1*time.Second)

	pake1 := Pake1ParamRequest(ctx.X.as_bytes())
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

	pake3 := Pake3ParamRequest(ctx.cA)
	udpr.WriteTo(pake3, &addr)
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