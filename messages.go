package gomat

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	randm "math/rand"

	"github.com/tom-code/gomat/mattertlv"
)


type ProtocolId uint16
const PROTOCOL_ID_SECURE_CHANNEL ProtocolId = 0
const PROTOCOL_ID_INTERACTION    ProtocolId = 1

type Opcode byte
const SEC_CHAN_OPCODE_ACK        Opcode = 0x10
const SEC_CHAN_OPCODE_PBKDF_REQ  Opcode = 0x20
const SEC_CHAN_OPCODE_PBKDF_RESP Opcode = 0x21
const SEC_CHAN_OPCODE_PAKE1      Opcode = 0x22
const SEC_CHAN_OPCODE_PAKE2      Opcode = 0x23
const SEC_CHAN_OPCODE_PAKE3      Opcode = 0x24
const SEC_CHAN_OPCODE_STATUS_REP Opcode = 0x40

const INTERACTION_OPCODE_STATUS_RSP   Opcode = 0x1
const INTERACTION_OPCODE_READ_REQ     Opcode = 0x2
const INTERACTION_OPCODE_REPORT_DATA  Opcode = 0x5
const INTERACTION_OPCODE_INVOKE_REQ   Opcode = 0x8
const INTERACTION_OPCODE_INVOKE_RSP   Opcode = 0x9

type MessageHeader struct {
	flags byte
	sessionId uint16
	securityFlags byte
	messageCounter uint32
	sourceNodeId []byte
	destinationNodeId []byte
}

type ProtocolMessageHeader struct {
	exchangeFlags byte
	Opcode Opcode
	exchangeId uint16
	ProtocolId ProtocolId
	ackCounter uint32
}

func (m *ProtocolMessageHeader)decode(data *bytes.Buffer) {
	m.exchangeFlags, _ = data.ReadByte()
	opcode, _ := data.ReadByte()
	m.Opcode = Opcode(opcode)
	binary.Read(data, binary.LittleEndian, &m.exchangeId)
	binary.Read(data, binary.LittleEndian, &m.ProtocolId)
	if (m.exchangeFlags & 0x2) != 0 {
		binary.Read(data, binary.LittleEndian, &m.ackCounter)
	}
}


func (m *MessageHeader)Dump()  {
	fmt.Printf("  flags      : %d\n", m.flags)
	fmt.Printf("  sessionId  : %d\n", m.sessionId)
	fmt.Printf("  secFlags   : %d\n", m.securityFlags)
	fmt.Printf("  msgCounter : %d\n", m.messageCounter)
	fmt.Printf("  srcNode    : %v\n", m.sourceNodeId)
	fmt.Printf("  dstNode    : %v\n", m.destinationNodeId)
}

func (m *ProtocolMessageHeader)Dump()  {
	fmt.Printf("  prot       :\n")
	fmt.Printf("    exchangeFlags : %d\n", m.exchangeFlags)
	fmt.Printf("    opcode        : 0x%x\n", m.Opcode)
	fmt.Printf("    exchangeId    : %d\n", m.exchangeId)
	fmt.Printf("    protocolId    : %d\n", m.ProtocolId)
	fmt.Printf("    ackCounter    : %d\n", m.ackCounter)
}
func (m *ProtocolMessageHeader)encode(data *bytes.Buffer) {
	data.WriteByte(m.exchangeFlags)
	data.WriteByte(byte(m.Opcode))
	binary.Write(data, binary.LittleEndian, uint16(m.exchangeId))
	binary.Write(data, binary.LittleEndian, uint16(m.ProtocolId))
}


func (m *MessageHeader)calcMessageFlags() byte {
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

func (m *MessageHeader) encode(data *bytes.Buffer) {
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


func (m *MessageHeader) decode(data *bytes.Buffer) error {
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



func pBKDFParamRequest(exchange uint16) []byte {
	var buffer bytes.Buffer

	prot:= ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode: SEC_CHAN_OPCODE_PBKDF_REQ,
		exchangeId: exchange,
		ProtocolId: PROTOCOL_ID_SECURE_CHANNEL,
	}
	prot.encode(&buffer)	
	var tlvx mattertlv.TLVBuffer
	tlvx.WriteAnonStruct()
	initiator_random := make([]byte, 32)
	rand.Read(initiator_random)
	tlvx.WriteOctetString(0x1, initiator_random)  // initiator random
	tlvx.WriteUInt(0x2, mattertlv.TYPE_UINT_2, 0x0001)      //initator session-id
	tlvx.WriteUInt(0x3, mattertlv.TYPE_UINT_1, 0x00)        // passcode id
	tlvx.WriteBool(0x4, false)                    // has pbkdf
	tlvx.WriteAnonStructEnd()
	buffer.Write(tlvx.Bytes())
	return buffer.Bytes()
}


func pake1ParamRequest(exchange uint16, key []byte) []byte {
	var buffer bytes.Buffer

	prot:= ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode: SEC_CHAN_OPCODE_PAKE1,
		exchangeId: exchange,
		ProtocolId: PROTOCOL_ID_SECURE_CHANNEL,
	}
	prot.encode(&buffer)	

	var tlvx mattertlv.TLVBuffer
	tlvx.WriteAnonStruct()
	tlvx.WriteOctetString(0x1, key)
	tlvx.WriteAnonStructEnd()
	buffer.Write(tlvx.Bytes())
	return buffer.Bytes()
}

func pake3ParamRequest(exchange uint16, key []byte) []byte {
	var buffer bytes.Buffer
	prot:= ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode: SEC_CHAN_OPCODE_PAKE3,
		exchangeId: exchange,
		ProtocolId: PROTOCOL_ID_SECURE_CHANNEL,
	}
	prot.encode(&buffer)

	var tlvx mattertlv.TLVBuffer
	tlvx.WriteAnonStruct()
	tlvx.WriteOctetString(0x1, key)
	tlvx.WriteAnonStructEnd()
	buffer.Write(tlvx.Bytes())
	return buffer.Bytes()
}

func ackGen(p ProtocolMessageHeader, counter uint32) []byte {
	var buffer bytes.Buffer

	prot:= ProtocolMessageHeader{
		exchangeFlags: 3,
		Opcode: SEC_CHAN_OPCODE_ACK,
		exchangeId: p.exchangeId,
		ProtocolId: PROTOCOL_ID_SECURE_CHANNEL,
	}
	prot.encode(&buffer)
	binary.Write(&buffer, binary.LittleEndian, counter)
	return buffer.Bytes()
}


type StatusReportElements struct {
	GeneralCode   uint16
	ProtocolId   uint32
	ProtocolCode uint16
}

type DecodedGeneric struct {
	MessageHeader MessageHeader
	ProtocolHeader ProtocolMessageHeader
	Tlv mattertlv.TlvItem
	payload []byte
	StatusReport StatusReportElements
}



func EncodeInvokeCommand(endpoint, cluster, command byte, payload []byte) []byte {

	var tlvx mattertlv.TLVBuffer
	tlvx.WriteAnonStruct()
		tlvx.WriteBool(0, false)
		tlvx.WriteBool(1, false)
		tlvx.WriteArray(2)
			tlvx.WriteAnonStruct()
				tlvx.WriteList(0)
					tlvx.WriteUInt(0, mattertlv.TYPE_UINT_1, uint64(endpoint))
					tlvx.WriteUInt(1, mattertlv.TYPE_UINT_1, uint64(cluster))
					tlvx.WriteUInt(2, mattertlv.TYPE_UINT_1, uint64(command))
				tlvx.WriteAnonStructEnd()
				tlvx.WriteStruct(1)
					//tlv.writeOctetString(0, payload)
					tlvx.WriteRaw(payload)
				tlvx.WriteAnonStructEnd()
			tlvx.WriteAnonStructEnd()
		tlvx.WriteAnonStructEnd()
		tlvx.WriteUInt(0xff, mattertlv.TYPE_UINT_1, 10)
	tlvx.WriteAnonStructEnd()


	var buffer bytes.Buffer
	buffer.WriteByte(5) // flags
	buffer.WriteByte(byte(INTERACTION_OPCODE_INVOKE_REQ)) // opcode
	var exchange_id uint16
	exchange_id = uint16(randm.Intn(0xffff))
	binary.Write(&buffer, binary.LittleEndian, exchange_id)
	var protocol_id uint16 = uint16(PROTOCOL_ID_INTERACTION)
	binary.Write(&buffer, binary.LittleEndian, protocol_id)
	buffer.Write(tlvx.Bytes())

	return buffer.Bytes()
}

func EncodeInvokeRead(endpoint, cluster, attr byte) []byte {

	var tlvx mattertlv.TLVBuffer
	tlvx.WriteAnonStruct()
		tlvx.WriteArray(0)
			tlvx.WriteAnonList()
				//tlv.writeList(0)
					//tlv.writeBool(0, false)
					tlvx.WriteUInt(2, mattertlv.TYPE_UINT_1, uint64(endpoint))
					tlvx.WriteUInt(3, mattertlv.TYPE_UINT_1, uint64(cluster))
					tlvx.WriteUInt(4, mattertlv.TYPE_UINT_1, uint64(attr))
				//tlv.writeAnonStructEnd()
			tlvx.WriteAnonStructEnd()
		tlvx.WriteAnonStructEnd()
		tlvx.WriteBool(3, true)
		tlvx.WriteUInt(0xff, mattertlv.TYPE_UINT_1, 10)
	tlvx.WriteAnonStructEnd()


	var buffer bytes.Buffer
	buffer.WriteByte(5) // flags
	buffer.WriteByte(byte(INTERACTION_OPCODE_READ_REQ)) // opcode
	var exchange_id uint16
	binary.Write(&buffer, binary.LittleEndian, exchange_id)
	var protocol_id uint16 = uint16(PROTOCOL_ID_INTERACTION)
	binary.Write(&buffer, binary.LittleEndian, protocol_id)
	buffer.Write(tlvx.Bytes())

	return buffer.Bytes()
}
