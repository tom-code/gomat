package gomat

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/tom-code/gomat/tlvdec"
)

type Channel struct {
	Udp net.PacketConn
	Remote_address net.UDPAddr
}

func NewChannel(remote_ip net.IP, remote_port, local_port int) Channel {
	var out Channel
	out.Remote_address = net.UDPAddr{
		IP : remote_ip,
		Port: remote_port,
	}
	var err error
	out.Udp, err = net.ListenPacket("udp", fmt.Sprintf(":%d", local_port))
	if err != nil {
		panic(err)
	}
	return out
}

func (ch *Channel)send(data []byte) {
	ch.Udp.WriteTo(data, &ch.Remote_address)
}
func (ch *Channel)receive() ([]byte, error) {
	buf := make([]byte, 1024)
	n, _, errx := ch.Udp.ReadFrom(buf)
	if errx != nil {
		panic(errx)
	}
	return buf[:n], nil
}

func make_nonce3(counter uint32, node []byte) []byte{
	var n bytes.Buffer
	n.WriteByte(0)
	binary.Write(&n, binary.LittleEndian, counter)
	n.Write(node)
	return n.Bytes()
}



type SecureChannel struct {
	Udp *Channel
	encrypt_key []byte
	decrypt_key []byte
	remote_node []byte
	local_node []byte
	Counter uint32
	session int
}

func (sc *SecureChannel) Receive() DecodedGeneric {
	data, _ := sc.Udp.receive()
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

	if out.proto.protocolId == 0 {
		if out.proto.opcode == 0x10 {  // standalone ack
			return sc.Receive()
		}
	}

	ack := AckGen(out.proto, out.msg.messageCounter)
	sc.Send(ack)

	if out.proto.protocolId == 0 {
		if out.proto.opcode == 0x40 {  // status report
			return out
		}
	}
	if len(out.payload) > 0 {
		out.Tlv = tlvdec.Decode(out.payload)
	}
	return out
}

func (sc *SecureChannel)Send(data []byte) {

	sc.Counter = sc.Counter + 1
	var buffer bytes.Buffer
	msg := Message {
		sessionId: uint16(sc.session),
		securityFlags: 0,
		messageCounter: sc.Counter,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
	}
	msg.encodeBase(&buffer)
	if len(sc.encrypt_key) == 0 {
		buffer.Write(data)
	} else {

		header_slice := buffer.Bytes()
		add2 := make([]byte, len(header_slice))
		copy(add2, header_slice)

		nonce := make_nonce3(sc.Counter, sc.local_node)

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


	sc.Udp.send(buffer.Bytes())
}