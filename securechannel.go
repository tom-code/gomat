package gomat

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/tom-code/gomat/ccm"
	"github.com/tom-code/gomat/mattertlv"
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

func (ch *Channel)send(data []byte) error {
	_, err := ch.Udp.WriteTo(data, &ch.Remote_address)
	return err
}
func (ch *Channel)receive() ([]byte, error) {
	buf := make([]byte, 1024)
	n, _, errx := ch.Udp.ReadFrom(buf)
	if errx != nil {
		return []byte{}, errx
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

func (sc *SecureChannel) Receive() (DecodedGeneric, error) {
	sc.Udp.Udp.SetReadDeadline(time.Now().Add(time.Second*3))
	data, err := sc.Udp.receive()
	if err != nil {
		return DecodedGeneric{}, err
	}
	decode_buffer := bytes.NewBuffer(data)
	var out DecodedGeneric
	out.msg.decodeBase(decode_buffer)
	add := data[:len(data)-decode_buffer.Len()]
	proto := decode_buffer.Bytes()


	if len(sc.decrypt_key) > 0 {
		nonce := make_nonce3(out.msg.messageCounter, sc.remote_node)
		c, err := aes.NewCipher(sc.decrypt_key)
		if err != nil {
			return DecodedGeneric{}, err
		}
		ccm, err := ccm.NewCCMWithNonceAndTagSizes(c, len(nonce), 16)
		if err != nil {
			return DecodedGeneric{}, err
		}
		ciphertext := proto
		decbuf := []byte{}
		outx, err := ccm.Open(decbuf, nonce, ciphertext, add)
		if err != nil {
			return DecodedGeneric{}, err
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
			buf := bytes.NewBuffer(out.payload)
			binary.Read(buf, binary.LittleEndian, &out.statusReport.GeneralCode)
			binary.Read(buf, binary.LittleEndian, &out.statusReport.ProtocolId)
			binary.Read(buf, binary.LittleEndian, &out.statusReport.ProtocolCode)
			return out, nil
		}
	}
	if len(out.payload) > 0 {
		out.Tlv = mattertlv.Decode(out.payload)
	}
	return out, nil
}

func (sc *SecureChannel)Send(data []byte) error {

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
			return err
		}
		ccm, err := ccm.NewCCMWithNonceAndTagSizes(c, len(nonce), 16)
		if err != nil {
			return err
		}
		CipherText := ccm.Seal(nil, nonce, data, add2)
		buffer.Write(CipherText)
	}


	err := sc.Udp.send(buffer.Bytes())
	return err
}