package mattertlv

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

type ElementType int

const TypeInt ElementType = 1
const TypeBool ElementType = 2
const TypeUTF8String ElementType = 3
const TypeOctetString ElementType = 4
const TypeList ElementType = 5
const TypeNull ElementType = 6

// TlvItem represents one TLV entry.
type TlvItem struct {
	Tag          int
	Type         ElementType
	detailedType string

	valueBool        bool
	valueInt         uint64
	valueString      string
	valueOctetString []byte
	valueList        []TlvItem
}

// GetChild returns slice of all child entries.
func (i TlvItem) GetChild() []TlvItem {
	return i.valueList
}

func (i TlvItem) GetItemWithTag(tag int) *TlvItem {
	for n, item := range i.valueList {
		if item.Tag == tag {
			return &i.valueList[n]
		}
	}
	return nil
}

// GetChild returns value of integer entry as int.
func (i TlvItem) GetInt() int {
	return int(i.valueInt)
}

// GetChild returns value of integer entry as uint64.
func (i TlvItem) GetUint64() uint64 {
	return uint64(i.valueInt)
}
func (i TlvItem) GetOctetString() []byte {
	return i.valueOctetString
}
func (i TlvItem) GetString() string {
	return i.valueString
}
func (i TlvItem) Dump(pad int) {
	pads := strings.Repeat("-", pad)
	fmt.Printf(pads)
	fmt.Printf("tag:%4d type:%10s internal_type:", i.Tag, i.detailedType)
	switch i.Type {
	case TypeNull:
		fmt.Printf("null\n")
	case TypeInt:
		fmt.Printf("int val:%d\n", i.valueInt)
	case TypeBool:
		fmt.Printf("bool val:%v\n", i.valueBool)
	case TypeUTF8String:
		fmt.Printf("string val:%s\n", i.valueString)
	case TypeOctetString:
		fmt.Printf("bytes val:%s\n", hex.EncodeToString(i.valueOctetString))
	case TypeList:
		fmt.Printf("struct:\n")
		for _, ii := range i.valueList {
			ii.Dump(pad + 2)
		}
		//fmt.Println()
	default:
		fmt.Printf("unknown %d\n", i.Type)
	}
}

func (i TlvItem) DumpWithDict(pad int, path string, dictionary map[string]string) {
	path_me := fmt.Sprintf("%s.%d", path, i.Tag)
	pads := strings.Repeat(" ", pad)
	//fmt.Printf("path %s\n", path_me)
	fmt.Printf(pads)
	name, ok := dictionary[path_me]
	if !ok {
		name = fmt.Sprintf("%d", i.Tag)
	}
	fmt.Printf("%s: ", name)
	switch i.Type {
	case TypeNull:
		fmt.Printf("null\n")
	case TypeInt:
		fmt.Printf("%d\n", i.valueInt)
	case TypeBool:
		fmt.Printf("%v\n", i.valueBool)
	case TypeUTF8String:
		fmt.Printf("%s\n", i.valueString)
	case TypeOctetString:
		fmt.Printf("%s\n", hex.EncodeToString(i.valueOctetString))
	case TypeList:
		fmt.Printf("\n")
		for _, ii := range i.valueList {
			ii.DumpWithDict(pad+2, path_me, dictionary)
		}
	default:
		fmt.Printf("unknown %d\n", i.Type)
	}
}

func (i TlvItem) GetItemRec(tag []int) *TlvItem {
	if len(tag) == 0 {
		return &i
	}
	if i.Type == TypeList {
		for _, d := range i.valueList {
			if d.Tag == tag[0] {
				return d.GetItemRec(tag[1:])
			}
		}
	}
	return nil
}

func (i TlvItem) GetOctetStringRec(tag []int) []byte {
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

func (i TlvItem) GetIntRec(tag []int) (uint64, error) {
	if len(tag) == 0 {
		return i.valueInt, nil
	}
	if i.Type == TypeList {
		for _, d := range i.valueList {
			if d.Tag == tag[0] {
				return d.GetIntRec(tag[1:])
			}
		}
	}
	return 0, fmt.Errorf("no found")
}

func readByte(buf *bytes.Buffer) int {
	tmp, err := buf.ReadByte()
	if err != nil {
		panic(err)
	}
	return int(tmp)
}

func readTag(tagctrl byte, item *TlvItem, buf *bytes.Buffer) {
	if tagctrl == 1 {
		item.Tag = readByte(buf)
	}
}

func decode(buf *bytes.Buffer, container *TlvItem) {
	for buf.Len() > 0 {
		current := TlvItem{}
		fb, _ := buf.ReadByte()
		tp := fb & 0x1f
		tagctrl := fb >> 5
		switch tp {
		case 0:
			current.detailedType = "int[1]"
			current.Type = TypeInt
			readTag(tagctrl, &current, buf)
			current.valueInt = uint64(readByte(buf))
		case 1:
			current.detailedType = "int[2]"
			current.Type = TypeInt
			readTag(tagctrl, &current, buf)
			var tmp uint16
			binary.Read(buf, binary.LittleEndian, tmp)
			current.valueInt = uint64(tmp)
		case 2:
			current.detailedType = "int[4]"
			current.Type = TypeInt
			readTag(tagctrl, &current, buf)
			var tmp uint32
			binary.Read(buf, binary.LittleEndian, tmp)
			current.valueInt = uint64(tmp)
		case 3:
			current.detailedType = "int[8]"
			current.Type = TypeInt
			readTag(tagctrl, &current, buf)
			var tmp uint64
			binary.Read(buf, binary.LittleEndian, tmp)
			current.valueInt = uint64(tmp)
		case 4:
			current.detailedType = "uint[1]"
			current.Type = TypeInt
			readTag(tagctrl, &current, buf)
			current.valueInt = uint64(readByte(buf))
		case 5:
			current.detailedType = "uint[2]"
			current.Type = TypeInt
			readTag(tagctrl, &current, buf)
			var tmp uint16
			binary.Read(buf, binary.LittleEndian, &tmp)
			current.valueInt = uint64(tmp)
		case 6:
			current.detailedType = "uint[4]"
			current.Type = TypeInt
			readTag(tagctrl, &current, buf)
			var tmp uint32
			binary.Read(buf, binary.LittleEndian, &tmp)
			current.valueInt = uint64(tmp)
		case 7:
			current.detailedType = "uint[8]"
			current.Type = TypeInt
			readTag(tagctrl, &current, buf)
			var tmp uint64
			binary.Read(buf, binary.LittleEndian, &tmp)
			current.valueInt = uint64(tmp)
		case 8:
			current.detailedType = "bool-false"
			current.Type = TypeBool
			readTag(tagctrl, &current, buf)
			current.valueBool = false
		case 9:
			current.detailedType = "bool-true"
			current.Type = TypeBool
			readTag(tagctrl, &current, buf)
			current.valueBool = true
		case 0xa:
			panic("")
		case 0xb:
			panic("")
		case 0xc:
			current.detailedType = "utf8string[1]"
			current.Type = TypeUTF8String
			readTag(tagctrl, &current, buf)
			size := readByte(buf)
			current.valueOctetString = make([]byte, size)
			buf.Read(current.valueOctetString)
			current.valueString = string(current.valueOctetString)
		case 0x10:
			current.detailedType = "octetstring[1]"
			current.Type = TypeOctetString
			readTag(tagctrl, &current, buf)
			size := readByte(buf)
			current.valueOctetString = make([]byte, size)
			buf.Read(current.valueOctetString)
		case 0x11:
			current.detailedType = "octetstring[2]"
			current.Type = TypeOctetString
			readTag(tagctrl, &current, buf)
			var size uint16
			binary.Read(buf, binary.LittleEndian, &size)
			current.valueOctetString = make([]byte, size)
			buf.Read(current.valueOctetString)
		case 0x14:
			current.detailedType = "null"
			current.Type = TypeNull
			readTag(tagctrl, &current, buf)
		case 0x15:
			current.detailedType = "struct"
			current.Type = TypeList
			readTag(tagctrl, &current, buf)
			decode(buf, &current)
		case 0x16:
			current.detailedType = "array"
			current.Type = TypeList
			readTag(tagctrl, &current, buf)
			decode(buf, &current)
		case 0x17:
			current.detailedType = "list"
			current.Type = TypeList
			readTag(tagctrl, &current, buf)
			decode(buf, &current)
		case 0x18:
			return
		default:
			panic(fmt.Sprintf("unknown type %x", tp))
		}
		container.valueList = append(container.valueList, current)
	}
}

// Decode decodes binary TLV into structure represented by TlvItem.
func Decode(in []byte) TlvItem {
	buf := bytes.NewBuffer(in)
	root := &TlvItem{
		Type: TypeList,
	}
	decode(buf, root)
	return root.valueList[0]
}
