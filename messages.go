package gomat

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	randm "math/rand"

	"github.com/tom-code/gomat/tlvdec"
	"github.com/tom-code/gomat/tlvenc"
)


const PROTOCOL_ID_SECURE_CHANNEL = 0

const SEC_CHAN_OPCODE_ACK        = 0x10
const SEC_CHAN_OPCODE_PBKDF_REQ  = 0x20
const SEC_CHAN_OPCODE_PBKDF_RESP = 0x21
const SEC_CHAN_OPCODE_PAKE1      = 0x22
const SEC_CHAN_OPCODE_PAKE2      = 0x23
const SEC_CHAN_OPCODE_PAKE3      = 0x24
const SEC_CHAN_OPCODE_STATUS_REP = 0x40



type ProtocolMessage struct {
	exchangeFlags byte
	opcode byte
	exchangeId uint16
	protocolId uint16
	ackCounter uint32
}
func (m *ProtocolMessage)decode(data *bytes.Buffer) {
	m.exchangeFlags, _ = data.ReadByte()
	m.opcode, _ = data.ReadByte()
	binary.Read(data, binary.LittleEndian, &m.exchangeId)
	binary.Read(data, binary.LittleEndian, &m.protocolId)
	if (m.exchangeFlags & 0x2) != 0 {
		binary.Read(data, binary.LittleEndian, &m.ackCounter)
	}
}

type Message struct {
	flags byte
	sessionId uint16
	securityFlags byte
	messageCounter uint32
	sourceNodeId []byte
	destinationNodeId []byte
	prot ProtocolMessage
}

func (m *Message)dump()  {
	fmt.Printf("  flags      : %d\n", m.flags)
	fmt.Printf("  sessionId  : %d\n", m.sessionId)
	fmt.Printf("  secFlags   : %d\n", m.securityFlags)
	fmt.Printf("  msgCounter : %d\n", m.messageCounter)
	fmt.Printf("  srcNode    : %v\n", m.sourceNodeId)
	fmt.Printf("  dstNode    : %v\n", m.destinationNodeId)
	fmt.Printf("  prot       :\n")
	fmt.Printf("    exchangeFlags : %d\n", m.prot.exchangeFlags)
	fmt.Printf("    opcode        : 0x%x\n", m.prot.opcode)
	fmt.Printf("    exchangeId    : %d\n", m.prot.exchangeId)
	fmt.Printf("    protocolId    : %d\n", m.prot.protocolId)
	fmt.Printf("    ackCounter    : %d\n", m.prot.ackCounter)
}

func (m *ProtocolMessage)dump()  {
	fmt.Printf("  prot       :\n")
	fmt.Printf("    exchangeFlags : %d\n", m.exchangeFlags)
	fmt.Printf("    opcode        : 0x%x\n", m.opcode)
	fmt.Printf("    exchangeId    : %d\n", m.exchangeId)
	fmt.Printf("    protocolId    : %d\n", m.protocolId)
	fmt.Printf("    ackCounter    : %d\n", m.ackCounter)
}
func (m *ProtocolMessage)encode(data *bytes.Buffer) {
	data.WriteByte(m.exchangeFlags)
	data.WriteByte(m.opcode)
	binary.Write(data, binary.LittleEndian, uint16(m.exchangeId))
	binary.Write(data, binary.LittleEndian, uint16(m.protocolId))
}


func (m *Message)calcMessageFlags() byte {
	var out byte
	out = 0 // version hardcoded = 0

	if len(m.sourceNodeId) == 8 {
		out = out | 4
	}

	dsiz := 0
	if len(m.destinationNodeId) == 2 {
		dsiz = 2
	} else if len(m.destinationNodeId) == 8 {
		dsiz = 1
	}

	out = out | byte(dsiz)
	return out
}

func (m *Message) encodeBase(data *bytes.Buffer) {
	data.WriteByte(m.calcMessageFlags())
	binary.Write(data, binary.LittleEndian, uint16(m.sessionId))
	data.WriteByte(m.securityFlags)
	binary.Write(data, binary.LittleEndian, uint32(m.messageCounter))
	if len(m.sourceNodeId) == 8 {
		data.Write(m.sourceNodeId)
	}
	if len(m.destinationNodeId) > 0 {
		data.Write(m.destinationNodeId)
	}
}


func (m *Message) decode(data *bytes.Buffer) error {
	var err error
	m.flags, err = data.ReadByte()
	if err != nil {
		return err
	}
	binary.Read(data, binary.LittleEndian, &m.sessionId)
	m.securityFlags, err = data.ReadByte()
	if err != nil {
		return err
	}
	binary.Read(data, binary.LittleEndian, &m.messageCounter)
	if (m.flags & 4) != 0 {
		m.sourceNodeId = make([]byte, 8)
		_, err := data.Read(m.sourceNodeId)
		if err != nil {
			return err
		}
	}
	if ((m.flags & 3 )!= 0) {
		dsiz := 0
		if (m.flags & 3) == 1 {
			dsiz = 8
		} else if (m.flags & 3) == 2 {
			dsiz = 2
		}
		if dsiz != 0 {
			m.destinationNodeId = make([]byte, dsiz)
			_, err := data.Read(m.destinationNodeId)
			if err != nil {
				return err
			}
		}
	}
	m.prot.exchangeFlags, err = data.ReadByte()
	if err != nil {
		return err
	}
	m.prot.opcode, err = data.ReadByte()
	if err != nil {
		return err
	}
	binary.Read(data, binary.LittleEndian, &m.prot.exchangeId)
	binary.Read(data, binary.LittleEndian, &m.prot.protocolId)
	if (m.prot.exchangeFlags & 0x2) != 0 {
		binary.Read(data, binary.LittleEndian, &m.prot.ackCounter)
	}
	return nil
}

func (m *Message) decodeBase(data *bytes.Buffer) error {
	var err error
	m.flags, err = data.ReadByte()
	if err != nil {
		return err
	}
	binary.Read(data, binary.LittleEndian, &m.sessionId)
	m.securityFlags, err = data.ReadByte()
	if err != nil {
		return err
	}
	binary.Read(data, binary.LittleEndian, &m.messageCounter)
	if (m.flags & 4) != 0 {
		m.sourceNodeId = make([]byte, 8)
		_, err := data.Read(m.sourceNodeId)
		if err != nil {
			return err
		}
	}
	if ((m.flags & 3 )!= 0) {
		dsiz := 0
		if (m.flags & 3) == 1 {
			dsiz = 8
		} else if (m.flags & 3) == 2 {
			dsiz = 2
		}
		if dsiz != 0 {
			m.destinationNodeId = make([]byte, dsiz)
			_, err := data.Read(m.destinationNodeId)
			if err != nil {
				return err
			}
		}
	}
	return nil
}



func PBKDFParamRequest(exchange uint16) []byte {
	var buffer bytes.Buffer

	prot:= ProtocolMessage{
		exchangeFlags: 5,
		opcode: SEC_CHAN_OPCODE_PBKDF_REQ,
		exchangeId: exchange,
		protocolId: 0x00,
	}
	prot.encode(&buffer)	
	var tlv tlvenc.TLVBuffer
	tlv.WriteAnonStruct()
	initiator_random := make([]byte, 32)
	rand.Read(initiator_random)
	tlv.WriteOctetString(0x1, initiator_random)  // initiator random
	tlv.WriteUInt(0x2, tlvenc.TYPE_UINT_2, 0x0001)      //initator session-id
	tlv.WriteUInt(0x3, tlvenc.TYPE_UINT_1, 0x00)        // passcode id
	tlv.WriteBool(0x4, false)                    // has pbkdf
	tlv.WriteAnonStructEnd()
	buffer.Write(tlv.Bytes())
	return buffer.Bytes()
}


func Pake1ParamRequest(exchange uint16, key []byte) []byte {
	var buffer bytes.Buffer

	prot:= ProtocolMessage{
		exchangeFlags: 5,
		opcode: SEC_CHAN_OPCODE_PAKE1,
		exchangeId: exchange,
		protocolId: 0x00,
	}
	prot.encode(&buffer)	

	var tlv tlvenc.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteOctetString(0x1, key)
	tlv.WriteAnonStructEnd()
	buffer.Write(tlv.Bytes())
	return buffer.Bytes()
}

func Pake3ParamRequest(exchange uint16, key []byte) []byte {
	var buffer bytes.Buffer
	prot:= ProtocolMessage{
		exchangeFlags: 5,
		opcode: SEC_CHAN_OPCODE_PAKE3,
		exchangeId: exchange,
		protocolId: 0x00,
	}
	prot.encode(&buffer)

	var tlv tlvenc.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteOctetString(0x1, key)
	tlv.WriteAnonStructEnd()
	buffer.Write(tlv.Bytes())
	return buffer.Bytes()
}

func AckGen(p ProtocolMessage, counter uint32) []byte {
	var buffer bytes.Buffer

	prot:= ProtocolMessage{
		exchangeFlags: 3,
		opcode: SEC_CHAN_OPCODE_ACK,
		exchangeId: p.exchangeId,
		protocolId: 0x00,
	}
	prot.encode(&buffer)
	binary.Write(&buffer, binary.LittleEndian, counter)
	return buffer.Bytes()
}




func decodegen(data []byte) DecodedGeneric {
	//log.Printf("goinf to decvode %s\n", hex.EncodeToString(data))
	out := DecodedGeneric{}
	buf := bytes.NewBuffer(data)
	out.msg.decode(buf)
	//out.msg.dump()

	tlvdata := make([]byte, buf.Available())
	n, _ := buf.Read(tlvdata)
	//log.Printf("tlv data %s", hex.EncodeToString(tlvdata[:n]))
	out.Tlv = tlvdec.Decode(tlvdata[:n])
	out.payload = tlvdata[:n]

	return out
}


type DecodedGeneric struct {
	msg Message
	proto ProtocolMessage
	Tlv tlvdec.TlvItem
	payload []byte
}



func InvokeCommand(endpoint, cluster, command byte, payload []byte) []byte {

	var tlv tlvenc.TLVBuffer
	tlv.WriteAnonStruct()
		tlv.WriteBool(0, false)
		tlv.WriteBool(1, false)
		tlv.WriteArray(2)
			tlv.WriteAnonStruct()
				tlv.WriteList(0)
					tlv.WriteUInt(0, tlvenc.TYPE_UINT_1, uint64(endpoint))
					tlv.WriteUInt(1, tlvenc.TYPE_UINT_1, uint64(cluster))
					tlv.WriteUInt(2, tlvenc.TYPE_UINT_1, uint64(command))
				tlv.WriteAnonStructEnd()
				tlv.WriteStruct(1)
					//tlv.writeOctetString(0, payload)
					tlv.WriteRaw(payload)
				tlv.WriteAnonStructEnd()
			tlv.WriteAnonStructEnd()
		tlv.WriteAnonStructEnd()
		tlv.WriteUInt(0xff, tlvenc.TYPE_UINT_1, 10)
	tlv.WriteAnonStructEnd()


	var buffer bytes.Buffer
	buffer.WriteByte(5) // flags
	buffer.WriteByte(8) // opcode
	var exchange_id uint16
	exchange_id = uint16(randm.Intn(0xffff))
	binary.Write(&buffer, binary.LittleEndian, exchange_id)
	var protocol_id uint16 
	protocol_id = 1
	binary.Write(&buffer, binary.LittleEndian, protocol_id)
	buffer.Write(tlv.Bytes())

	return buffer.Bytes()
}

func InvokeRead(endpoint, cluster, attr byte) []byte {

	var tlv tlvenc.TLVBuffer
	tlv.WriteAnonStruct()
		tlv.WriteArray(0)
			tlv.WriteAnonList()
				//tlv.writeList(0)
					//tlv.writeBool(0, false)
					tlv.WriteUInt(2, tlvenc.TYPE_UINT_1, uint64(endpoint))
					tlv.WriteUInt(3, tlvenc.TYPE_UINT_1, uint64(cluster))
					tlv.WriteUInt(4, tlvenc.TYPE_UINT_1, uint64(attr))
				//tlv.writeAnonStructEnd()
			tlv.WriteAnonStructEnd()
		tlv.WriteAnonStructEnd()
		tlv.WriteBool(3, true)
		tlv.WriteUInt(0xff, tlvenc.TYPE_UINT_1, 10)
	tlv.WriteAnonStructEnd()


	var buffer bytes.Buffer
	buffer.WriteByte(5) // flags
	buffer.WriteByte(2) // opcode
	var exchange_id uint16
	binary.Write(&buffer, binary.LittleEndian, exchange_id)
	var protocol_id uint16 
	protocol_id = 1
	binary.Write(&buffer, binary.LittleEndian, protocol_id)
	buffer.Write(tlv.Bytes())

	return buffer.Bytes()
}
