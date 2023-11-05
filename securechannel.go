package gomat

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/tom-code/gomat/ccm"
	"github.com/tom-code/gomat/mattertlv"
)

type UdpChannel struct {
	Udp net.PacketConn
	Remote_address net.UDPAddr
}

func StartUdpChannel(remote_ip net.IP, remote_port, local_port int) (*UdpChannel, error) {
	var out *UdpChannel = new(UdpChannel)
	out.Remote_address = net.UDPAddr{
		IP : remote_ip,
		Port: remote_port,
	}
	var err error
	out.Udp, err = net.ListenPacket("udp", fmt.Sprintf(":%d", local_port))
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (ch *UdpChannel)send(data []byte) error {
	_, err := ch.Udp.WriteTo(data, &ch.Remote_address)
	return err
}
func (ch *UdpChannel)receive() ([]byte, error) {
	buf := make([]byte, 1024*10)
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
	Udp *UdpChannel
	encrypt_key []byte
	decrypt_key []byte
	remote_node []byte
	local_node []byte
	Counter uint32
	session int
}

func StartSecureChannel(remote_ip net.IP, remote_port, local_port int) (SecureChannel, error) {
	udp, err := StartUdpChannel(remote_ip, remote_port, local_port)
	if err != nil {
		return SecureChannel{}, err
	}
	return SecureChannel{
		Udp:     udp,
		Counter: uint32(rand.Intn(0xffffffff)),
	}, nil
}

func (sc *SecureChannel) Receive() (DecodedGeneric, error) {
	sc.Udp.Udp.SetReadDeadline(time.Now().Add(time.Second*3))
	data, err := sc.Udp.receive()
	if err != nil {
		return DecodedGeneric{}, err
	}
	decode_buffer := bytes.NewBuffer(data)
	var out DecodedGeneric
	out.MessageHeader.decode(decode_buffer)
	add := data[:len(data)-decode_buffer.Len()]
	proto := decode_buffer.Bytes()


	if len(sc.decrypt_key) > 0 {
		nonce := make_nonce3(out.MessageHeader.messageCounter, sc.remote_node)
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

		out.ProtocolHeader.decode(decoder)
		if len(decoder.Bytes()) > 0 {
			tlvdata := make([]byte, decoder.Len())
			n, _ := decoder.Read(tlvdata)
			out.payload = tlvdata[:n]
		}
	} else {
		out.ProtocolHeader.decode(decode_buffer)
		if len(decode_buffer.Bytes()) > 0 {
			tlvdata := make([]byte, decode_buffer.Len())
			n, _ := decode_buffer.Read(tlvdata)
			out.payload = tlvdata[:n]
		}
	}

	if out.ProtocolHeader.ProtocolId == 0 {
		if out.ProtocolHeader.Opcode == SEC_CHAN_OPCODE_ACK {  // standalone ack
			return sc.Receive()
		}
	}

	ack := ackGen(out.ProtocolHeader, out.MessageHeader.messageCounter)
	sc.Send(ack)

	if out.ProtocolHeader.ProtocolId == 0 {
		if out.ProtocolHeader.Opcode == SEC_CHAN_OPCODE_STATUS_REP {  // status report
			buf := bytes.NewBuffer(out.payload)
			binary.Read(buf, binary.LittleEndian, &out.StatusReport.GeneralCode)
			binary.Read(buf, binary.LittleEndian, &out.StatusReport.ProtocolId)
			binary.Read(buf, binary.LittleEndian, &out.StatusReport.ProtocolCode)
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
	msg := MessageHeader {
		sessionId: uint16(sc.session),
		securityFlags: 0,
		messageCounter: sc.Counter,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
	}
	msg.encode(&buffer)
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

func (sc *SecureChannel)Close() {
	sr := EncodeStatusReport(StatusReportElements{
		GeneralCode: 0,
		ProtocolId: 0,
		ProtocolCode: 3, //close session
	})
	sc.Send(sr)
	sc.Udp.Udp.Close()
}