package main

import (
	"encoding/hex"
	"log"
	"net"
)

func main() {

	test1()
	test2()

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
	log.Println(respbin)
	respstr := hex.EncodeToString(respbin)
	log.Println(respstr)
	decode(respbin)
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