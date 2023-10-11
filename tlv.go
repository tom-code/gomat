package main

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"gomat/tlvdec"
	"log"
)

const TYPE_UINT_1 = 4
const TYPE_UINT_2 = 5
const TYPE_UINT_4 = 6
const TYPE_UINT_8 = 7


const PROTOCOL_ID_SECURE_CHANNEL = 0

const SEC_CHAN_OPCODE_ACK        = 0x10
const SEC_CHAN_OPCODE_PBKDF_REQ  = 0x20
const SEC_CHAN_OPCODE_PBKDF_RESP = 0x21
const SEC_CHAN_OPCODE_PAKE1      = 0x22
const SEC_CHAN_OPCODE_PAKE2      = 0x23
const SEC_CHAN_OPCODE_PAKE3      = 0x24
const SEC_CHAN_OPCODE_STATUS_REP = 0x40

type TLVBuffer struct {
	data bytes.Buffer
}

type TLVBufferDec struct {
	data *bytes.Buffer
}

func (b *TLVBufferDec) checkAndSkip(d byte) error {
	o, err := b.data.ReadByte()
	if err != nil {
		return err
	}
	if o != d {
		b.data.UnreadByte()
		return fmt.Errorf("unexpected byte %x, expected %x", o, d)
	}
	return nil
}

func (b *TLVBufferDec) checkAndSkipBytes(d []byte) error {
	did_read := 0
	for _, now := range d {
		o, err := b.data.ReadByte()
		if err != nil {
			return err
		}
		did_read = did_read + 1
		if o != now {
			for i:=0; i<did_read; i++ {
				b.data.UnreadByte()
			}
			return fmt.Errorf("unexpected byte %x, expected %x", o, d)
		}
	}
	return nil
}

func (b *TLVBufferDec) readOctetString(itag byte) ([]byte, error) {
	ctrl, err := b.data.ReadByte()
	if err != nil {
		return nil, err
	}
	tagtype := ctrl >>5
	if tagtype != 1 {
		return nil, fmt.Errorf("can't handle tag type %x", ctrl)
	}
	tag, err := b.data.ReadByte()
	if err != nil {
		return nil, err
	}
	if tag != itag {
		return nil, fmt.Errorf("unexpected tag %d, expected %d", tag, itag)
	}
	tp := ctrl & 0x1f
	if tp != 0x10 {
		return nil, fmt.Errorf("can't handle octet string type %x", ctrl)
	}
	s, err := b.data.ReadByte()
	if err != nil {
		return nil, err
	}
	out := make([]byte, s)
	n, err := b.data.Read(out)
	if err != nil {
		return nil, err
	}
	if n != int(s) {
		return nil, fmt.Errorf("not able to read %d bytes", s)
	}
	return out, nil
}

func (b *TLVBufferDec) readUInt(itag byte) (uint64, error) {
	ctrl, err := b.data.ReadByte()
	if err != nil {
		return 0, err
	}
	tagtype := ctrl >>5
	if tagtype != 1 {
		return 0, fmt.Errorf("can't handle tag type %x", ctrl)
	}
	tag, err := b.data.ReadByte()
	if err != nil {
		return 0, err
	}
	if tag != itag {
		return 0, fmt.Errorf("unexpected tag %d, expected %d", tag, itag)
	}
	tp := ctrl & 0x1f
	if tp == TYPE_UINT_1 {
		o, err := b.data.ReadByte()
		if err != nil {
			return 0, err
		}
		return uint64(o), nil

	}
	if tp == TYPE_UINT_2 {
		var o uint16
		binary.Read(b.data, binary.LittleEndian, &o)
		if err != nil {
			return 0, err
		}
		return uint64(o), nil

	}
	if tp == TYPE_UINT_4 {
		var o uint32
		binary.Read(b.data, binary.LittleEndian, &o)
		if err != nil {
			return 0, err
		}
		return uint64(o), nil

	}
	if tp == TYPE_UINT_8 {
		var o uint64
		binary.Read(b.data, binary.LittleEndian, &o)
		if err != nil {
			return 0, err
		}
		return uint64(o), nil

	}
	return 0, fmt.Errorf("can't handle uint string type %x", ctrl)
}


func (b *TLVBuffer) writeRaw(raw []byte) {
	b.data.Write(raw)
}


func (b *TLVBuffer) writeControl(ctrl byte) {
	binary.Write(&b.data, binary.BigEndian, ctrl)
}

func (b *TLVBuffer) writeTagContentSpecific(tag byte) {
	binary.Write(&b.data, binary.BigEndian, tag)
}

func (b *TLVBuffer) writeUInt(tag byte, typ int, val uint64) {
	var ctrl byte
	ctrl = 0x1 << 5
	ctrl = ctrl | byte(typ)
	b.data.WriteByte(ctrl)
	b.data.WriteByte(tag)
	switch typ {
	case TYPE_UINT_1: b.data.WriteByte(byte(val))
	case TYPE_UINT_2: binary.Write(&b.data, binary.LittleEndian, uint16(val))
	case TYPE_UINT_4: binary.Write(&b.data, binary.LittleEndian, uint32(val))
	case TYPE_UINT_8: binary.Write(&b.data, binary.LittleEndian, uint64(val))
	}
}

func (b *TLVBuffer) writeOctetString(tag byte, data []byte) {
	var ctrl byte
	ctrl = 0x1 << 5
	if len(data) > 0xff {
		ctrl = ctrl | 0x11
		b.data.WriteByte(ctrl)
		b.data.WriteByte(tag)
		var ln uint16
		ln = uint16(len(data))
		binary.Write(&b.data, binary.LittleEndian, ln)
	} else {
		ctrl = ctrl | 0x10
		b.data.WriteByte(ctrl)
		b.data.WriteByte(tag)
		b.data.WriteByte(byte(len(data)))
	}
	b.data.Write(data)
}

func (b *TLVBuffer) writeBool(tag byte, val bool) {
	var ctrl byte
	ctrl = 0x1 << 5
	if val {
		ctrl = ctrl | 0x9
	} else {
		ctrl = ctrl | 0x8
	}
	b.data.WriteByte(ctrl)
	b.data.WriteByte(tag)
}

func (b *TLVBuffer) writeAnonStruct() {
	b.data.WriteByte(0x15)
}
func (b *TLVBuffer) writeStruct(tag byte) {
	b.data.WriteByte(0x35)
	b.data.WriteByte(tag)
}
func (b *TLVBuffer) writeArray(tag byte) {
	b.data.WriteByte(0x36)
	b.data.WriteByte(tag)
}
func (b *TLVBuffer) writeList(tag byte) {
	b.data.WriteByte(0x37)
	b.data.WriteByte(tag)
}
func (b *TLVBuffer) writeAnonStructEnd() {
	b.data.WriteByte(0x18)
}


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
	binary.Read(data, binary.LittleEndian, m.exchangeId)
	binary.Read(data, binary.LittleEndian, m.protocolId)
	if (m.exchangeFlags & 0x2) != 0 {
		binary.Read(data, binary.LittleEndian, m.ackCounter)
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

func (m *Message) encode(data *bytes.Buffer) {
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

	data.WriteByte(m.prot.exchangeFlags)
	data.WriteByte(m.prot.opcode)
	binary.Write(data, binary.LittleEndian, uint16(m.prot.exchangeId))
	binary.Write(data, binary.LittleEndian, uint16(m.prot.protocolId))
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



func PBKDFParamRequest() []byte {
	var buffer bytes.Buffer
	msg := Message {
		sessionId: 0x0,
		securityFlags: 0,
		messageCounter: 1,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
		prot: ProtocolMessage{
			exchangeFlags: 5,
			opcode: SEC_CHAN_OPCODE_PBKDF_REQ,
			exchangeId: 0xba3e,
			protocolId: 0x00,
		},
	}
	msg.encode(&buffer)

	var tlv TLVBuffer
	tlv.writeAnonStruct()
	bytes, err := hex.DecodeString("bbcbd707308cb511a5b7909ee2e15eeeed2a24372f851499b2d0dfc9485eae8f")
	if err != nil {
		panic(err)
	}
	tlv.writeOctetString(0x1, bytes)             // initiator random
	tlv.writeUInt(0x2, TYPE_UINT_2, 0x0001)      //initator session-id
	tlv.writeUInt(0x3, TYPE_UINT_1, 0x00)        // passcode id
	tlv.writeBool(0x4, false)                     // has pbkdf
	tlv.writeAnonStructEnd()
	buffer.Write(tlv.data.Bytes())
	return buffer.Bytes()
}

type PBKDFParamResponse struct {
	initiatorRandom []byte
	responderRandom []byte
	responderSession int
	iterations int
	salt []byte
}
type PAKE2ParamResponse struct {
	pb []byte
	cb []byte
}

type StatusReport struct {
	generalCode uint16
	protocolId uint32
	protocolCode uint16
}
func (d StatusReport)dump() {
	fmt.Printf(" generalCode  : %d\n", d.generalCode)
	fmt.Printf(" protocolId   : %d\n", d.protocolId)
	fmt.Printf(" protocolCode : %d\n", d.protocolCode)
}

type AllResp struct {
	messageCounter uint32
	sourceNodeId []byte
	PBKDFParamResponse *PBKDFParamResponse
	PAKE2ParamResponse *PAKE2ParamResponse
	StatusReport StatusReport
}

func (d PBKDFParamResponse)dump() {
	fmt.Printf(" initiatorRandom : %s\n", hex.EncodeToString(d.initiatorRandom))
	fmt.Printf(" responderRandom : %s\n", hex.EncodeToString(d.responderRandom))
	fmt.Printf(" responderSession: %d\n", d.responderSession)
	fmt.Printf(" iterations      : %d\n", d.iterations)
	fmt.Printf(" salt            : %s\n", hex.EncodeToString(d.salt))
}

func decodeStatusReport(buf *bytes.Buffer) AllResp {
	log.Printf("status report data %s", hex.EncodeToString(buf.Bytes()))
	var StatusReport StatusReport
	binary.Read(buf, binary.LittleEndian, &StatusReport.generalCode)
	binary.Read(buf, binary.LittleEndian, &StatusReport.protocolId)
	binary.Read(buf, binary.LittleEndian, &StatusReport.protocolCode)

	return AllResp{
		StatusReport: StatusReport,
	}
}

func decodePBKDFParamResponse(buf *bytes.Buffer) AllResp {
	var out PBKDFParamResponse
	var tlv TLVBufferDec
	tlv.data = buf
	err := tlv.checkAndSkip(0x15)
	if err != nil {
		panic(err)
	}
	out.initiatorRandom, err = tlv.readOctetString(1)
	if err != nil {
		panic(err)
	}
	out.responderRandom, err = tlv.readOctetString(2)
	if err != nil {
		panic(err)
	}
	responderSession, err := tlv.readUInt(3)
	if err != nil {
		panic(err)
	}
	out.responderSession = int(responderSession)
	err = tlv.checkAndSkipBytes([]byte{0x35, 0x4})
	if err != nil {
		panic(err)
	}
	iterations, err := tlv.readUInt(1)
	if err != nil {
		panic(err)
	}
	out.iterations = int(iterations)
	out.salt, err = tlv.readOctetString(2)
	if err != nil {
		panic(err)
	}

	out.dump()

	var o AllResp
	o.PBKDFParamResponse = &out

	return o
}

func decodePAKE2ParamResponse(buf *bytes.Buffer) AllResp {
	log.Println("decoding pake2")
	var out PAKE2ParamResponse
	var tlv TLVBufferDec
	tlv.data = buf
	err := tlv.checkAndSkip(0x15)
	if err != nil {
		panic(err)
	}
	out.pb, err = tlv.readOctetString(1)
	if err != nil {
		panic(err)
	}
	out.cb, err = tlv.readOctetString(2)
	if err != nil {
		panic(err)
	}

	var o AllResp
	o.PAKE2ParamResponse = &out

	return o
}

func Pake1ParamRequest(key []byte, counter uint32) []byte {
	var buffer bytes.Buffer
	msg := Message {
		sessionId: 0x0,
		securityFlags: 0,
		messageCounter: counter,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
		prot: ProtocolMessage{
			exchangeFlags: 5,
			opcode: SEC_CHAN_OPCODE_PAKE1,
			exchangeId: 0xba3e,
			protocolId: 0x00,
		},
	}
	msg.encode(&buffer)

	var tlv TLVBuffer
	tlv.writeAnonStruct()
	tlv.writeOctetString(0x1, key)
	tlv.writeAnonStructEnd()
	buffer.Write(tlv.data.Bytes())
	return buffer.Bytes()
}

func Pake3ParamRequest(key []byte, counter uint32) []byte {
	var buffer bytes.Buffer
	msg := Message {
		sessionId: 0x0,
		securityFlags: 0,
		messageCounter: counter,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
		prot: ProtocolMessage{
			exchangeFlags: 5,
			//exchangeFlags: 7,
			opcode: SEC_CHAN_OPCODE_PAKE3,
			exchangeId: 0xba3e,
			protocolId: 0x00,
		},
	}
	msg.encode(&buffer)

	var tlv TLVBuffer
	tlv.writeAnonStruct()
	tlv.writeOctetString(0x1, key)
	tlv.writeAnonStructEnd()
	buffer.Write(tlv.data.Bytes())
	return buffer.Bytes()
}

func Ack(cnt uint32, counter uint32) []byte {
	var buffer bytes.Buffer
	msg := Message {
		sessionId: 0x0,
		securityFlags: 0,
		messageCounter: cnt,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
		prot: ProtocolMessage{
			exchangeFlags: 3,
			//exchangeFlags: 7,
			opcode: SEC_CHAN_OPCODE_ACK,
			exchangeId: 0xba3e,
			protocolId: 0x00,
		},
	}
	msg.encode(&buffer)
	binary.Write(&buffer, binary.LittleEndian, counter)


	return buffer.Bytes()
}

func AckS(cnt uint32, counter uint32) []byte {
	var buffer bytes.Buffer
	msg := Message {
		sessionId: 0x0,
		securityFlags: 0,
		messageCounter: cnt,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
		prot: ProtocolMessage{
			exchangeFlags: 3,
			//exchangeFlags: 7,
			opcode: SEC_CHAN_OPCODE_ACK,
			exchangeId: 0xba3f,
			protocolId: 0x00,
		},
	}
	msg.encode(&buffer)
	binary.Write(&buffer, binary.LittleEndian, counter)


	return buffer.Bytes()
}
func AckS2(cnt uint32, counter uint32, session_id uint16) []byte {
	var buffer bytes.Buffer
	msg := Message {
		sessionId: session_id,
		securityFlags: 0,
		messageCounter: cnt,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
		prot: ProtocolMessage{
			exchangeFlags: 3,
			//exchangeFlags: 7,
			opcode: SEC_CHAN_OPCODE_ACK,
			exchangeId: 0xba3f,
			protocolId: 0x00,
		},
	}
	msg.encode(&buffer)
	binary.Write(&buffer, binary.LittleEndian, counter)


	return buffer.Bytes()
}



func decode(data []byte) AllResp {
	var msg Message
	buf := bytes.NewBuffer(data)
	msg.decode(buf)
	msg.dump()

	switch msg.prot.protocolId {
	case PROTOCOL_ID_SECURE_CHANNEL:
		switch msg.prot.opcode {
		case SEC_CHAN_OPCODE_PBKDF_RESP:
			resp := decodePBKDFParamResponse(buf)
			resp.messageCounter = msg.messageCounter
			resp.sourceNodeId = msg.sourceNodeId
			return resp
		case SEC_CHAN_OPCODE_PAKE2:
			resp := decodePAKE2ParamResponse(buf)
			resp.messageCounter = msg.messageCounter
			resp.sourceNodeId = msg.sourceNodeId
			return resp
		case SEC_CHAN_OPCODE_STATUS_REP:
			resp := decodeStatusReport(buf)
			resp.messageCounter = msg.messageCounter
			resp.sourceNodeId = msg.sourceNodeId
			return resp
		}
	}
	return AllResp{}
}

func decodegen(data []byte) DecodedGeneric {
	log.Printf("goinf to decvode %s\n", hex.EncodeToString(data))
	out := DecodedGeneric{}
	buf := bytes.NewBuffer(data)
	out.msg.decode(buf)
	out.msg.dump()

	tlvdata := make([]byte, buf.Available())
	n, _ := buf.Read(tlvdata)
	log.Printf("tlv data %s", hex.EncodeToString(tlvdata[:n]))
	out.tlv = tlvdec.Decode(tlvdata[:n])
	out.payload = tlvdata[:n]

	return out
}


func Secured(session uint16, counter uint32, data []byte, key []byte, nonce []byte) []byte {
	var buffer bytes.Buffer
	msg := Message {
		sessionId: session,
		securityFlags: 0,
		messageCounter: counter,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
	}
	msg.encodeBase(&buffer)

	var add bytes.Buffer
	add.WriteByte(4) //flags
	binary.Write(&add, binary.LittleEndian, uint16(msg.sessionId))
	add.WriteByte(msg.securityFlags)
	binary.Write(&add, binary.LittleEndian, msg.messageCounter)
	add.Write(msg.sourceNodeId)

	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ccm, err := NewCCMWithNonceAndTagSizes(c, len(nonce), 16)
	if err != nil {
		panic(err)
	}
	CipherText := ccm.Seal(nil, nonce, data, add.Bytes())
	buffer.Write(CipherText)


	//buffer.Write(data)
	//return CipherText
	return buffer.Bytes()
}

type DecodedGeneric struct {
	msg Message
	proto ProtocolMessage
	tlv tlvdec.TlvItem
	payload []byte
}

func decodeSecured(in []byte, key []byte) DecodedGeneric {
	var decoded DecodedGeneric
	//var msg Message
	buf := bytes.NewBuffer(in)
	decoded.msg.decodeBase(buf)
	decoded.msg.dump()

	var add bytes.Buffer
	add.WriteByte(decoded.msg.flags)
	binary.Write(&add, binary.LittleEndian, uint16(decoded.msg.sessionId))
	add.WriteByte(decoded.msg.securityFlags)
	binary.Write(&add, binary.LittleEndian, decoded.msg.messageCounter)

	nonce := make_nonce(decoded.msg.messageCounter)
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ccm, err := NewCCMWithNonceAndTagSizes(c, len(nonce), 16)
	if err != nil {
		panic(err)
	}
	ciphertext := in[len(in)-buf.Len():]
	decbuf := []byte{}
	out, err := ccm.Open(decbuf, nonce, ciphertext, add.Bytes())
	if err != nil {
		panic(err)
	}


	decoder := bytes.NewBuffer(out)

	decoded.proto.decode(decoder)
	decoded.tlv = tlvdec.Decode(decoder.Bytes())

	return decoded

}

/*
func invokeCommand(endpoint, cluster, command byte, payload []byte) []byte {

	var tlv TLVBuffer
	tlv.writeAnonStruct()
		tlv.writeBool(0, false)
		tlv.writeBool(1, false)
		tlv.writeArray(2)
			tlv.writeAnonStruct()
				tlv.writeList(0)
					tlv.writeUInt(0, TYPE_UINT_1, uint64(endpoint))
					tlv.writeUInt(1, TYPE_UINT_1, uint64(cluster))
					tlv.writeUInt(2, TYPE_UINT_1, uint64(command))
				tlv.writeAnonStructEnd()
				tlv.writeStruct(1)
					tlv.writeOctetString(0, payload)
				tlv.writeAnonStructEnd()
			tlv.writeAnonStructEnd()
		tlv.writeAnonStructEnd()
		tlv.writeUInt(0xff, TYPE_UINT_1, 10)
	tlv.writeAnonStructEnd()


	var buffer bytes.Buffer
	buffer.WriteByte(5) // flags
	buffer.WriteByte(8) // opcode
	var exchange_id uint16
	binary.Write(&buffer, binary.LittleEndian, exchange_id)
	var protocol_id uint16 
	protocol_id = 1
	binary.Write(&buffer, binary.LittleEndian, protocol_id)
	buffer.Write(tlv.data.Bytes())

	return buffer.Bytes()
}*/

func invokeCommand2(endpoint, cluster, command byte, payload []byte) []byte {

	var tlv TLVBuffer
	tlv.writeAnonStruct()
		tlv.writeBool(0, false)
		tlv.writeBool(1, false)
		tlv.writeArray(2)
			tlv.writeAnonStruct()
				tlv.writeList(0)
					tlv.writeUInt(0, TYPE_UINT_1, uint64(endpoint))
					tlv.writeUInt(1, TYPE_UINT_1, uint64(cluster))
					tlv.writeUInt(2, TYPE_UINT_1, uint64(command))
				tlv.writeAnonStructEnd()
				tlv.writeStruct(1)
					//tlv.writeOctetString(0, payload)
					tlv.writeRaw(payload)
				tlv.writeAnonStructEnd()
			tlv.writeAnonStructEnd()
		tlv.writeAnonStructEnd()
		tlv.writeUInt(0xff, TYPE_UINT_1, 10)
	tlv.writeAnonStructEnd()


	var buffer bytes.Buffer
	buffer.WriteByte(5) // flags
	buffer.WriteByte(8) // opcode
	var exchange_id uint16
	binary.Write(&buffer, binary.LittleEndian, exchange_id)
	var protocol_id uint16 
	protocol_id = 1
	binary.Write(&buffer, binary.LittleEndian, protocol_id)
	buffer.Write(tlv.data.Bytes())

	return buffer.Bytes()
}

func Ack3(counter uint32) []byte {
	var buffer bytes.Buffer
	buffer.WriteByte(3) // flags
	buffer.WriteByte(SEC_CHAN_OPCODE_ACK) // opcode
	var exchange_id uint16
	binary.Write(&buffer, binary.LittleEndian, exchange_id)
	var protocol_id uint16 
	protocol_id = 0
	binary.Write(&buffer, binary.LittleEndian, protocol_id)
	binary.Write(&buffer, binary.LittleEndian, counter)
	return buffer.Bytes()
}