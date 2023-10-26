package onboarding_payload

import (
	"fmt"
	"strings"
)

const qr_alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-."

func a2n(a byte) uint32 {
	for i:=0; i<len(qr_alphabet); i++ {
		if qr_alphabet[i] == a {
			return uint32(i)
		}
	}
	panic("")
}


type BitBuffer struct {
	bytes []byte
	current_byte int
	current_bit int
	total_bytes int
}

func (bb *BitBuffer)add_byte(n byte) {
	bb.total_bytes += 1
	bb.bytes = append(bb.bytes, n)
}

func (bb *BitBuffer)dump() {
	for _, b := range bb.bytes {
		for i:=0; i<8; i++ {
			if b&1 == 1 {
				fmt.Printf("1")
			} else {
				fmt.Printf("0")
			}
			b = b >> 1
		}
	}
	fmt.Printf("\n")
}

func (bb *BitBuffer)get() byte {
	b := bb.bytes[bb.current_byte]
	out := (b>>bb.current_bit)&1
	bb.current_bit +=1
	if bb.current_bit == 8 {
		bb.current_byte += 1
		bb.current_bit = 0
	}
	return out
}

func (bb *BitBuffer)get_number(bits int) uint64 {
	var out uint64
	var mult uint64
	mult = 1
	for i:=0; i<bits; i++ {
		out += uint64(bb.get())*mult
		mult = mult*2
	}

	return out
}

func (bb *BitBuffer)get_bit(n int) byte {
	b_byte := n/8
	b_bit := n%8
	return (bb.bytes[b_byte]>>b_bit)&1
}

func (bb *BitBuffer)reset_ptr() {
	bb.current_bit = 0
	bb.current_byte = 0
}

func b38_decode(in string) BitBuffer {
	in_array := []string{}
	for len(in) >= 5 {
		in_array = append(in_array, in[:5])
		in = in[5:]
	}
	if len(in) > 0 {
		in_array = append(in_array, in)
	}

	var bb BitBuffer
	for _, a := range in_array {
		var b24 uint32
		mult := 1
		for _, n := range(a) {
			b24 += a2n(byte(n))*uint32(mult)
			mult *= 38
		}
		for i:=0; i<3; i++ {
			bb.add_byte(byte(b24&0xff))
			b24 = b24 >>8
		}
	}
	return bb
}

type QrContent struct {
	Version byte
	Vendor uint16
	Product uint16
	Discriminator uint16
	Discriminator4 uint16
	Passcode uint32
}

func (qr QrContent)Dump() {
	fmt.Printf("version:  %d\n", qr.Version)
	fmt.Printf("vendor:   %d\n", qr.Vendor)
	fmt.Printf("product:  %d\n", qr.Product)
	fmt.Printf("passcode: %d\n", qr.Passcode)
	fmt.Printf("discriminator: %d\n", qr.Discriminator)
}

func DecodeQrText(in string) QrContent {
	if !strings.HasPrefix(in, "MT:") {
		panic("wrong qr")
	}
	in = in[3:]
	var out QrContent
	bb := b38_decode(in)

	bb.reset_ptr()
	out.Version = byte(bb.get_number(3))
	out.Vendor = uint16(bb.get_number(16))
	out.Product = uint16(bb.get_number(16))
	bb.get_number(2) // custom flow
	bb.get_number(8) // discovery capabilities
	out.Discriminator = uint16(bb.get_number(12))
	out.Passcode = uint32(bb.get_number(27))
	return out
}

