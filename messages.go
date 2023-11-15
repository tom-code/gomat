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

const ProtocolIdSecureChannel ProtocolId = 0
const ProtocolIdInteraction ProtocolId = 1

type Opcode byte

const SEC_CHAN_OPCODE_ACK Opcode = 0x10
const SEC_CHAN_OPCODE_PBKDF_REQ Opcode = 0x20
const SEC_CHAN_OPCODE_PBKDF_RESP Opcode = 0x21
const SEC_CHAN_OPCODE_PAKE1 Opcode = 0x22
const SEC_CHAN_OPCODE_PAKE2 Opcode = 0x23
const SEC_CHAN_OPCODE_PAKE3 Opcode = 0x24
const SEC_CHAN_OPCODE_STATUS_REP Opcode = 0x40

const INTERACTION_OPCODE_STATUS_RSP Opcode = 0x1
const INTERACTION_OPCODE_READ_REQ Opcode = 0x2
const INTERACTION_OPCODE_SUBSC_REQ Opcode = 0x3
const INTERACTION_OPCODE_SUBSC_RSP Opcode = 0x4
const INTERACTION_OPCODE_REPORT_DATA Opcode = 0x5
const INTERACTION_OPCODE_INVOKE_REQ Opcode = 0x8
const INTERACTION_OPCODE_INVOKE_RSP Opcode = 0x9
const INTERACTION_OPCODE_TIMED_REQ Opcode = 0xa

const exchangeFlagsInitiator = 1
const exchangeFlagsAcknowledge = 2

type MessageHeader struct {
	flags             byte
	sessionId         uint16
	securityFlags     byte
	messageCounter    uint32
	sourceNodeId      []byte
	destinationNodeId []byte
}

type ProtocolMessageHeader struct {
	exchangeFlags byte
	Opcode        Opcode
	ExchangeId    uint16
	ProtocolId    ProtocolId
	ackCounter    uint32
}

func (m *ProtocolMessageHeader) Decode(data *bytes.Buffer) {
	m.exchangeFlags, _ = data.ReadByte()
	opcode, _ := data.ReadByte()
	m.Opcode = Opcode(opcode)
	binary.Read(data, binary.LittleEndian, &m.ExchangeId)
	binary.Read(data, binary.LittleEndian, &m.ProtocolId)
	if (m.exchangeFlags & 0x2) != 0 {
		binary.Read(data, binary.LittleEndian, &m.ackCounter)
	}
}

func (m *MessageHeader) Dump() {
	fmt.Printf("  flags      : %d\n", m.flags)
	fmt.Printf("  sessionId  : %d\n", m.sessionId)
	fmt.Printf("  secFlags   : %d\n", m.securityFlags)
	fmt.Printf("  msgCounter : %d\n", m.messageCounter)
	fmt.Printf("  srcNode    : %v\n", m.sourceNodeId)
	fmt.Printf("  dstNode    : %v\n", m.destinationNodeId)
}

func (m *ProtocolMessageHeader) Dump() {
	fmt.Printf("  protocol message:\n")
	fmt.Printf("    exchangeFlags : %d\n", m.exchangeFlags)
	fmt.Printf("    opcode        : 0x%x\n", m.Opcode)
	fmt.Printf("    exchangeId    : %d\n", m.ExchangeId)
	fmt.Printf("    protocolId    : %d\n", m.ProtocolId)
	fmt.Printf("    ackCounter    : %d\n", m.ackCounter)
}
func (m *ProtocolMessageHeader) Encode(data *bytes.Buffer) {
	data.WriteByte(m.exchangeFlags)
	data.WriteByte(byte(m.Opcode))
	binary.Write(data, binary.LittleEndian, uint16(m.ExchangeId))
	binary.Write(data, binary.LittleEndian, uint16(m.ProtocolId))
}

func (m *MessageHeader) calcMessageFlags() byte {
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

func (m *MessageHeader) Encode(data *bytes.Buffer) {
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

func (m *MessageHeader) Decode(data *bytes.Buffer) error {
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
	if (m.flags & 3) != 0 {
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

	prot := ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode:        SEC_CHAN_OPCODE_PBKDF_REQ,
		ExchangeId:    exchange,
		ProtocolId:    ProtocolIdSecureChannel,
	}
	prot.Encode(&buffer)
	var tlvx mattertlv.TLVBuffer
	tlvx.WriteAnonStruct()
	initiator_random := make([]byte, 32)
	rand.Read(initiator_random)
	tlvx.WriteOctetString(0x1, initiator_random)       // initiator random
	tlvx.WriteUInt(0x2, mattertlv.TYPE_UINT_2, 0x0001) //initator session-id
	tlvx.WriteUInt(0x3, mattertlv.TYPE_UINT_1, 0x00)   // passcode id
	tlvx.WriteBool(0x4, false)                         // has pbkdf
	tlvx.WriteAnonStructEnd()
	buffer.Write(tlvx.Bytes())
	return buffer.Bytes()
}

func pake1ParamRequest(exchange uint16, key []byte) []byte {
	var buffer bytes.Buffer

	prot := ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode:        SEC_CHAN_OPCODE_PAKE1,
		ExchangeId:    exchange,
		ProtocolId:    ProtocolIdSecureChannel,
	}
	prot.Encode(&buffer)

	var tlvx mattertlv.TLVBuffer
	tlvx.WriteAnonStruct()
	tlvx.WriteOctetString(0x1, key)
	tlvx.WriteAnonStructEnd()
	buffer.Write(tlvx.Bytes())
	return buffer.Bytes()
}

func pake3ParamRequest(exchange uint16, key []byte) []byte {
	var buffer bytes.Buffer
	prot := ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode:        SEC_CHAN_OPCODE_PAKE3,
		ExchangeId:    exchange,
		ProtocolId:    ProtocolIdSecureChannel,
	}
	prot.Encode(&buffer)

	var tlvx mattertlv.TLVBuffer
	tlvx.WriteAnonStruct()
	tlvx.WriteOctetString(0x1, key)
	tlvx.WriteAnonStructEnd()
	buffer.Write(tlvx.Bytes())
	return buffer.Bytes()
}

func ackGen(p ProtocolMessageHeader, counter uint32) []byte {
	var buffer bytes.Buffer

	var eflags byte = exchangeFlagsAcknowledge
	if (p.exchangeFlags & exchangeFlagsInitiator) == 0 {
		eflags |= exchangeFlagsInitiator
	}
	prot := ProtocolMessageHeader{
		exchangeFlags: eflags,
		Opcode:        SEC_CHAN_OPCODE_ACK,
		ExchangeId:    p.ExchangeId,
		ProtocolId:    ProtocolIdSecureChannel,
	}
	prot.Encode(&buffer)
	binary.Write(&buffer, binary.LittleEndian, counter)
	return buffer.Bytes()
}

type StatusReportElements struct {
	GeneralCode  uint16
	ProtocolId   uint32
	ProtocolCode uint16
}

func (sr StatusReportElements) Dump() {
	fmt.Printf("  general code: %d\n", sr.GeneralCode)
	fmt.Printf("  protocol id: %d\n", sr.ProtocolId)
	fmt.Printf("  protocol code: %d\n", sr.ProtocolCode)
}

func (sr StatusReportElements) IsOk() bool {
	if sr.GeneralCode != 0 {
		return false
	}
	if sr.ProtocolId != 0 {
		return false
	}
	if sr.ProtocolCode != 0 {
		return false
	}
	return true
}

type DecodedGeneric struct {
	MessageHeader  MessageHeader
	ProtocolHeader ProtocolMessageHeader
	Tlv            mattertlv.TlvItem
	Payload        []byte
	StatusReport   StatusReportElements
}

func EncodeStatusReport(code StatusReportElements) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte(5)                                // flags
	buffer.WriteByte(byte(SEC_CHAN_OPCODE_STATUS_REP)) // opcode
	var exchange_id uint16
	exchange_id = uint16(randm.Intn(0xffff))
	binary.Write(&buffer, binary.LittleEndian, exchange_id)
	var protocol_id uint16 = uint16(ProtocolIdSecureChannel)
	binary.Write(&buffer, binary.LittleEndian, protocol_id)
	binary.Write(&buffer, binary.LittleEndian, code.GeneralCode)
	binary.Write(&buffer, binary.LittleEndian, code.ProtocolId)
	binary.Write(&buffer, binary.LittleEndian, code.ProtocolCode)

	return buffer.Bytes()
}

func EncodeIMInvokeRequest(endpoint byte, cluster uint16, command byte, payload []byte, timed bool, exchange uint16) []byte {

	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteBool(0, false)
	tlv.WriteBool(1, timed)
	tlv.WriteArray(2)
	tlv.WriteAnonStruct()
	tlv.WriteList(0)
	tlv.WriteUInt(0, mattertlv.TYPE_UINT_1, uint64(endpoint))
	tlv.WriteUInt(1, mattertlv.TYPE_UINT_2, uint64(cluster))
	tlv.WriteUInt(2, mattertlv.TYPE_UINT_1, uint64(command))
	tlv.WriteAnonStructEnd()
	tlv.WriteStruct(1)
	//tlv.writeOctetString(0, payload)
	tlv.WriteRaw(payload)
	tlv.WriteAnonStructEnd()
	tlv.WriteAnonStructEnd()
	tlv.WriteAnonStructEnd()
	tlv.WriteUInt(0xff, mattertlv.TYPE_UINT_1, 10)
	tlv.WriteAnonStructEnd()

	var buffer bytes.Buffer
	prot := ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode:        INTERACTION_OPCODE_INVOKE_REQ,
		ExchangeId:    exchange,
		ProtocolId:    ProtocolIdInteraction,
	}
	prot.Encode(&buffer)
	buffer.Write(tlv.Bytes())

	return buffer.Bytes()
}

func EncodeIMReadRequest(endpoint byte, cluster uint16, attr byte) []byte {

	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteArray(0)
	tlv.WriteAnonList()
	tlv.WriteUInt(2, mattertlv.TYPE_UINT_1, uint64(endpoint))
	tlv.WriteUInt(3, mattertlv.TYPE_UINT_2, uint64(cluster))
	tlv.WriteUInt(4, mattertlv.TYPE_UINT_1, uint64(attr))
	tlv.WriteAnonStructEnd()
	tlv.WriteAnonStructEnd()
	tlv.WriteBool(3, true)
	tlv.WriteUInt(0xff, mattertlv.TYPE_UINT_1, 10)
	tlv.WriteAnonStructEnd()

	var buffer bytes.Buffer

	prot := ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode:        INTERACTION_OPCODE_READ_REQ,
		ExchangeId:    0,
		ProtocolId:    ProtocolIdInteraction,
	}
	prot.Encode(&buffer)
	buffer.Write(tlv.Bytes())

	return buffer.Bytes()
}

func EncodeIMSubscribeRequest(endpoint byte, cluster uint16, event byte) []byte {

	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteBool(0, false) // keep
	tlv.WriteUInt16(1, 10)  // min interval
	tlv.WriteUInt16(2, 50)  // max interval
	tlv.WriteArray(4)
	tlv.WriteAnonList()
	tlv.WriteUInt8(1, endpoint)
	tlv.WriteUInt16(2, cluster)
	tlv.WriteUInt8(3, event)
	tlv.WriteBool(4, true) // urgent
	tlv.WriteAnonStructEnd()
	tlv.WriteAnonStructEnd()
	/*tlvx.WriteArray(5)
		tlvx.WriteAnonStruct()
				tlvx.WriteUInt(0, mattertlv.TYPE_UINT_1, uint64(100))
				tlvx.WriteUInt(1, mattertlv.TYPE_UINT_1, uint64(0))
		tlvx.WriteAnonStructEnd()
	tlvx.WriteAnonStructEnd()*/
	tlv.WriteBool(7, false) // fabric filtered
	tlv.WriteUInt(0xff, mattertlv.TYPE_UINT_1, 10)
	tlv.WriteAnonStructEnd()

	var buffer bytes.Buffer
	prot := ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode:        INTERACTION_OPCODE_SUBSC_REQ,
		ExchangeId:    0,
		ProtocolId:    ProtocolIdInteraction,
	}

	prot.Encode(&buffer)
	buffer.Write(tlv.Bytes())

	return buffer.Bytes()
}

func EncodeIMTimedRequest(exchange uint16, timeout uint16) []byte {
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteUInt16(0, timeout)
	tlv.WriteUInt(0xff, mattertlv.TYPE_UINT_1, 10)
	tlv.WriteAnonStructEnd()

	var buffer bytes.Buffer
	prot := ProtocolMessageHeader{
		exchangeFlags: 5,
		Opcode:        INTERACTION_OPCODE_TIMED_REQ,
		ExchangeId:    exchange,
		ProtocolId:    ProtocolIdInteraction,
	}

	prot.Encode(&buffer)
	buffer.Write(tlv.Bytes())

	return buffer.Bytes()
}

// EncodeIMStatusResponse encodes success IM InvokeResponse
func EncodeIMStatusResponse(exchange_id uint16, iflag byte) []byte {
	var tlv mattertlv.TLVBuffer
	tlv.WriteAnonStruct()
	tlv.WriteUInt8(0, 0)
	tlv.WriteAnonStructEnd()

	var buffer bytes.Buffer
	prot := ProtocolMessageHeader{
		exchangeFlags: 4 | iflag,
		Opcode:        INTERACTION_OPCODE_STATUS_RSP,
		ExchangeId:    exchange_id,
		ProtocolId:    ProtocolIdInteraction,
	}
	prot.Encode(&buffer)

	buffer.Write(tlv.Bytes())

	return buffer.Bytes()
}

// ParseImInvokeResponse parses IM InvokeResponse TLV
//   - returns 0 when success
//   - returns -1 when parsing did fail
//   - returned number > 0 is ClusterStatus code
func ParseImInvokeResponse(resp *mattertlv.TlvItem) int {
	common_status := resp.GetItemRec([]int{1, 0, 1, 1, 0})
	if common_status == nil {
		return -1
	}
	if common_status.GetInt() == 0 {
		return 0
	}
	cluster_status := resp.GetItemRec([]int{1, 0, 1, 1, 1})
	if cluster_status == nil {
		return -1
	}
	return cluster_status.GetInt()
}
