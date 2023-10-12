package tlvdec

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

const TypeInt         = 1
const TypeBool 		  = 2
const TypeUTF8String  = 3
const TypeOctetString = 4
const TypeList		  = 5

type TlvItem struct {
	Tag int
	Type int
	types string

	valueBool   bool
	valueInt    uint64
	valueString string
	valueOctetString []byte
	valueList []TlvItem
}
func (i TlvItem)GetInt() int {
	return int(i.valueInt)
}
func (i TlvItem)GetUint64() uint64 {
	return uint64(i.valueInt)
}
func (i TlvItem)GetOctetString() []byte {
	return i.valueOctetString
}
func (i TlvItem)GetString() string {
	return i.valueString
}
func (i TlvItem)Dump(pad int) {
	pads := strings.Repeat("-", pad)
	fmt.Printf(pads)
	fmt.Printf("tag  %d <%s>", i.Tag, i.types)
	switch i.Type {
	case TypeInt: fmt.Printf("int %d\n", i.valueInt)
	case TypeBool: fmt.Printf("bool %v\n", i.valueBool)
	case TypeUTF8String: fmt.Printf("string %s\n", i.valueString)
	case TypeOctetString: fmt.Printf("bytes %s\n", hex.EncodeToString(i.valueOctetString))
	case TypeList:
		fmt.Printf("struct:\n")
		for _, ii := range i.valueList {
			ii.Dump(pad+2)
		}
		//fmt.Println()
	default: fmt.Printf("unknown %d\n", i.Type)
	}
}

func (i TlvItem)GetOctetStringRec(tag []int) []byte {
	if len(tag) == 0 {
		return i.valueOctetString
	}
	if i.Type == TypeList {
		for _, d := range i.valueList {
			if d.Tag == tag[0] {
				return d.GetOctetStringRec(tag[1:])
			}
		}
	}
	return []byte{}
}

func (i TlvItem)GetIntRec(tag []int) uint64 {
	if len(tag) == 0 {
		return i.valueInt
	}
	if i.Type == TypeList {
		for _, d := range i.valueList {
			if d.Tag == tag[0] {
				return d.GetIntRec(tag[1:])
			}
		}
	}
	return 0
}




func readByte(buf *bytes.Buffer) int {
	tmp, err := buf.ReadByte()
	if err != nil {
		panic(err)
	}
	return int(tmp)
}

func decode(buf *bytes.Buffer, container *TlvItem) {
	for buf.Len() > 0 {
		current := TlvItem{}
		fb, _ := buf.ReadByte()
		tp := fb & 0x1f
		tagctrl := fb>>5
		switch tp {
		case 0:
			current.Type = TypeInt
			current.Tag = readByte(buf)
			current.valueInt = uint64(readByte(buf))
		case 1:
			current.Type = TypeInt
			current.Tag = readByte(buf)
			var tmp uint16
			binary.Read(buf, binary.LittleEndian, tmp)
			current.valueInt = uint64(tmp)
		case 2:
			current.Type = TypeInt
			current.Tag = readByte(buf)
			var tmp uint32
			binary.Read(buf, binary.LittleEndian, tmp)
			current.valueInt = uint64(tmp)
		case 3:
			current.Type = TypeInt
			current.Tag = readByte(buf)
			var tmp uint64
			binary.Read(buf, binary.LittleEndian, tmp)
			current.valueInt = uint64(tmp)
		case 4:
			current.Type = TypeInt
			current.Tag = readByte(buf)
			current.valueInt = uint64(readByte(buf))
		case 5:
			current.Type = TypeInt
			current.Tag = readByte(buf)
			var tmp uint16
			binary.Read(buf, binary.LittleEndian, &tmp)
			current.valueInt = uint64(tmp)
		case 6:
			current.Type = TypeInt
			current.Tag = readByte(buf)
			var tmp uint32
			binary.Read(buf, binary.LittleEndian, &tmp)
			current.valueInt = uint64(tmp)
		case 7:
			current.Type = TypeInt
			current.Tag = readByte(buf)
			var tmp uint64
			binary.Read(buf, binary.LittleEndian, &tmp)
			current.valueInt = uint64(tmp)
		case 8:
			current.Type = TypeBool
			current.Tag = readByte(buf)
			current.valueBool = false
		case 9:
			current.Type = TypeBool
			current.Tag = readByte(buf)
			current.valueBool = true
		case 0xa:panic("")
		case 0xb:panic("")
		case 0xc:
			current.Type = TypeUTF8String
			current.Tag = readByte(buf)
			size := readByte(buf)
			current.valueOctetString = make([]byte, size)
			buf.Read(current.valueOctetString)
			current.valueString = string(current.valueOctetString)
		case 0x10:
			current.Type = TypeOctetString
			current.Tag = readByte(buf)
			size := readByte(buf)
			current.valueOctetString = make([]byte, size)
			buf.Read(current.valueOctetString)
		case 0x11:
			current.Type = TypeOctetString
			current.Tag = readByte(buf)
			var size uint16
			binary.Read(buf, binary.LittleEndian, &size)
			current.valueOctetString = make([]byte, size)
			buf.Read(current.valueOctetString)
		case 0x15:
			current.types = "struct"
			current.Type = TypeList
			if tagctrl == 1 {
				current.Tag = readByte(buf)
			}
			decode(buf, &current)
		case 0x16:
			current.types = "array"
			current.Type = TypeList
			if tagctrl == 1 {
				current.Tag = readByte(buf)
			}
			decode(buf, &current)
		case 0x17:
			current.types = "list"
			current.Type = TypeList
			if tagctrl == 1 {
				current.Tag = readByte(buf)
			}
			decode(buf, &current)
		case 0x18:
			return
		default:
			panic(fmt.Sprintf("unknown type %x", tp))
		}
		container.valueList = append(container.valueList, current)
	}
}

func Decode(in []byte) TlvItem {
	buf := bytes.NewBuffer(in)
	root := &TlvItem{
		Type: TypeList,
	}
	decode(buf, root)
	return root.valueList[0]
}


