package mattertlv

import (
	"bytes"
	"encoding/binary"
)

const TYPE_UINT_1 = 4
const TYPE_UINT_2 = 5
const TYPE_UINT_4 = 6
const TYPE_UINT_8 = 7

type TLVBuffer struct {
	data bytes.Buffer
}

func (b *TLVBuffer) WriteRaw(raw []byte) {
	b.data.Write(raw)
}

func (b *TLVBuffer) Bytes() []byte {
	return b.data.Bytes()
}

func (b *TLVBuffer) writeControl(ctrl byte) {
	binary.Write(&b.data, binary.BigEndian, ctrl)
}

func (b *TLVBuffer) writeTagContentSpecific(tag byte) {
	binary.Write(&b.data, binary.BigEndian, tag)
}

func (b *TLVBuffer) WriteUInt(tag byte, typ int, val uint64) {
	var ctrl byte
	ctrl = 0x1 << 5
	ctrl = ctrl | byte(typ)
	b.data.WriteByte(ctrl)
	b.data.WriteByte(tag)
	switch typ {
	case TYPE_UINT_1:
		b.data.WriteByte(byte(val))
	case TYPE_UINT_2:
		binary.Write(&b.data, binary.LittleEndian, uint16(val))
	case TYPE_UINT_4:
		binary.Write(&b.data, binary.LittleEndian, uint32(val))
	case TYPE_UINT_8:
		binary.Write(&b.data, binary.LittleEndian, uint64(val))
	}
}
func (b *TLVBuffer) WriteUInt8(tag byte, val byte) {
	var ctrl byte
	ctrl = 0x1 << 5
	ctrl = ctrl | TYPE_UINT_1
	b.data.WriteByte(ctrl)
	b.data.WriteByte(tag)
	b.data.WriteByte(byte(val))
}

func (b *TLVBuffer) WriteUInt16(tag byte, val uint16) {
	var ctrl byte
	ctrl = 0x1 << 5
	ctrl = ctrl | TYPE_UINT_2
	b.data.WriteByte(ctrl)
	b.data.WriteByte(tag)
	binary.Write(&b.data, binary.LittleEndian, val)
}

func (b *TLVBuffer) WriteUInt32(tag byte, val uint32) {
	var ctrl byte
	ctrl = 0x1 << 5
	ctrl = ctrl | TYPE_UINT_4
	b.data.WriteByte(ctrl)
	b.data.WriteByte(tag)
	binary.Write(&b.data, binary.LittleEndian, val)
}

func (b *TLVBuffer) WriteUInt64(tag byte, val uint64) {
	var ctrl byte
	ctrl = 0x1 << 5
	ctrl = ctrl | TYPE_UINT_8
	b.data.WriteByte(ctrl)
	b.data.WriteByte(tag)
	binary.Write(&b.data, binary.LittleEndian, val)
}

func (b *TLVBuffer) WriteOctetString(tag byte, data []byte) {
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

func (b *TLVBuffer) WriteBool(tag byte, val bool) {
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

func (b *TLVBuffer) WriteAnonStruct() {
	b.data.WriteByte(0x15)
}
func (b *TLVBuffer) WriteAnonList() {
	b.data.WriteByte(0x17)
}
func (b *TLVBuffer) WriteStruct(tag byte) {
	b.data.WriteByte(0x35)
	b.data.WriteByte(tag)
}
func (b *TLVBuffer) WriteArray(tag byte) {
	b.data.WriteByte(0x36)
	b.data.WriteByte(tag)
}
func (b *TLVBuffer) WriteList(tag byte) {
	b.data.WriteByte(0x37)
	b.data.WriteByte(tag)
}
func (b *TLVBuffer) WriteAnonStructEnd() {
	b.data.WriteByte(0x18)
}
