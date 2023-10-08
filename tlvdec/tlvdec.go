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


/*const t1 = "1528003601153500370024000024013e240205"+
           "183501"+
           "3000f3153001cb3081c83070020100300e310c300a060355040a0c034353523059301306072a8648ce3d020106082a8648ce3d03010703420004fd63186fce84c067f93e54f577b68a7e7ef72a9cefc547ad7c6046c22449350014b42ccdebbc97190592592ac2d9e6eb21b0a6427f908a7fdb6474ec8f6108aaa000300a06082a8648ce3d0403020348003045022067f1899819cd16ced0f0a9dc38b786741a51e5eb089b4a3e446eca7ae57567f70221008320de3db4b952c7276d797a88cc79459d789bf234e856b4fc935f97e8131942300220c4f68604b151d21f2afac9e61a745ade93fde7dce1c6615de543f230bd62dd8518"+
           "3001408f4f31f304a5821b477e26888fd19491382fba3ad23ea9ce8d95e6ee11000ca7c3c59d26118ec5efe422bdbff627b77faa1e1aadfb70a6d0d4b9e2a1096f8d3a"+
           "1818181824ff0a18"
const t2 = "1524013e18"
*/
const t1 = "1528002801360215370024000024013e2402061835013000f21530010101240201370324130218260480228127260580254d3a37062415012511570418240701240801300941049d77e774c633b939d20d518520552247f900e53b1998ba5b6f26133574b2bc5c4021ad65ef9875633f575f4b1cf81ce29e64095f3aa4c709f3da0ec4523b93d6370a350128011824020136030402040118300414ed97ef3e51b5bcd774a7cf98509d3f63f98bbd1a300514cd5ad18e0342d038cbc49f83df40ab500bcd2ed818300b4024da68cb9862a39eb536fd3763a05bb78df20bd286abdbc39fc4485a5d1110b3d75951fe564e9a7bed6b160e1cb5dae1bca7b1c87bdf0ce9556a291a06fc6913183001e71530010101240201370324140118260480228127260580254d3a37062413021824070124080130094104616c8167ad163beeb1b485e6045ec13ba3f8c960b9b2957bee83f3cd4b012a5ab1919424f6533da44d75f8f706274e3d9e111e6261f06b49d9d2c4d6c3c7ad06370a3501290118240260300414cd5ad18e0342d038cbc49f83df40ab500bcd2ed8300514f2462b7c9c033a9e0aecd9a11a338017dee97b6918300b40488bc743fb4c66c564377b9bdab42f58cb51ced113b6ed59d48a23f0838816972b85fa72f7d0922a6496c966aba01d796d06ed56993fcbec4e491ac3994af57b1830021074656d706f726172792069706b203031260369b601002504f1ff18181824ff0a18"

func Test1() {
	in, _ := hex.DecodeString(t1)
	out := Decode(in)
	out.Dump(0)
	d := out.GetOctetStringRec([]int{1,0,0,1,0})
	fmt.Println(d)

}

func Test2() {
	t2 := []byte {0x15, 0x30, 0x01, 0x01, 0x01, 0x24, 0x02, 0x01, 0x37, 0x03, 0x24, 0x14, 0x01, 0x18, 0x26, 0x04, 0x80, 0x22, 0x81, 0x27, 0x26, 0x05, 0x80, 0x25, 0x4d, 0x3a, 0x37, 0x06, 0x24, 0x14, 0x01, 0x18, 0x24, 0x07, 0x01, 0x24, 0x08, 0x01, 0x30, 0x09, 0x41, 0x04, 0x6f, 0xc3, 0x58, 0x61, 0xa7, 0x5f, 0x0b, 0x0d, 0x9d, 0x91, 0x20, 0x09, 0xcb, 0xec, 0x15, 0x67, 0x6f, 0x24, 0x67, 0x8a, 0xee, 0xab, 0x3d, 0xcb, 0x18, 0x9c, 0x3e, 0x02, 0x15, 0x00, 0x95, 0x2c, 0x19, 0x9d, 0xff, 0x86, 0x80, 0xbf, 0x0d, 0x3a, 0x4e, 0xe7, 0xc9, 0xf6, 0x00, 0x48, 0x13, 0x5f, 0xa2, 0x10, 0xf2, 0xa4, 0xd6, 0x08, 0x89, 0xed, 0x2e, 0x6c, 0xa1, 0x21, 0x66, 0xdc, 0x90, 0x4e, 0x37, 0x0a, 0x35, 0x01, 0x29, 0x01, 0x18, 0x24, 0x02, 0x60, 0x30, 0x04, 0x14, 0xf2, 0x46, 0x2b, 0x7c, 0x9c, 0x03, 0x3a, 0x9e, 0x0a, 0xec, 0xd9, 0xa1, 0x1a, 0x33, 0x80, 0x17, 0xde, 0xe9, 0x7b, 0x69, 0x30, 0x05, 0x14, 0xf2, 0x46, 0x2b, 0x7c, 0x9c, 0x03, 0x3a, 0x9e, 0x0a, 0xec, 0xd9, 0xa1, 0x1a, 0x33, 0x80, 0x17, 0xde, 0xe9, 0x7b, 0x69, 0x18, 0x30, 0x0b, 0x40, 0x4e, 0x31, 0x3f, 0xca, 0xea, 0x8b, 0x53, 0x1b, 0x24, 0xf4, 0x4f, 0xf1, 0x45, 0x13, 0x68, 0xee, 0xa2, 0x01, 0x8c, 0x89, 0xf7, 0x87, 0xf3, 0x9c, 0x0a, 0x52, 0xb8, 0x5b, 0x08, 0x09, 0x2f, 0xd4, 0x75, 0xc2, 0x85, 0xb9, 0x99, 0x33, 0xca, 0xaa, 0x30, 0xe1, 0x06, 0xe4, 0x3b, 0xd1, 0x29, 0xa9, 0xc6, 0x57, 0x98, 0xa1, 0xba, 0x5c, 0x06, 0x68, 0x0e, 0x42, 0xf3, 0x10, 0x4d, 0xd9, 0x33, 0x6e, 0x18}
	//t2 := []byte {0x15, 0x30, 0x01, 0x01, 0x01, 0x24, 0x02, 0x01, 0x37, 0x03, 0x24, 0x14, 0x01, 0x18, 0x26, 0x04, 0x80, 0x22, 0x81, 0x27, 0x26, 0x05, 0x80, 0x25, 0x4d, 0x3a, 0x37, 0x06, 0x24, 0x14, 0x01, 0x18, 0x24, 0x07, 0x01, 0x24, 0x08, 0x01, 0x30, 0x09, 0x41, 0x04, 0x6f, 0xc3, 0x58, 0x61, 0xa7, 0x5f, 0x0b, 0x0d, 0x9d, 0x91, 0x20, 0x09, 0xcb, 0xec, 0x15, 0x67, 0x6f, 0x24, 0x67, 0x8a, 0xee, 0xab, 0x3d, 0xcb, 0x18, 0x9c, 0x3e, 0x02, 0x15, 0x00, 0x95, 0x2c, 0x19, 0x9d, 0xff, 0x86, 0x80, 0xbf, 0x0d, 0x3a, 0x4e, 0xe7, 0xc9, 0xf6, 0x00, 0x48, 0x13, 0x5f, 0xa2, 0x10, 0xf2, 0xa4, 0xd6, 0x08, 0x89, 0xed, 0x2e, 0x6c, 0xa1, 0x21, 0x66, 0xdc, 0x90, 0x4e, 0x37, 0x0a, 0x35, 0x01, 0x29, 0x01, 0x18, 0x24, 0x02, 0x60, 0x30, 0x04, 0x14, 0xf2, 0x46, 0x2b, 0x7c, 0x9c, 0x03, 0x3a, 0x9e, 0x0a, 0xec, 0xd9, 0xa1, 0x1a, 0x33, 0x80, 0x17, 0xde, 0xe9, 0x7b, 0x69, 0x30, 0x05, 0x14, 0xf2, 0x46, 0x2b, 0x7c, 0x9c, 0x03, 0x3a, 0x9e, 0x0a, 0xec, 0xd9, 0xa1, 0x1a, 0x33, 0x80, 0x17, 0xde, 0xe9, 0x7b, 0x69, 0x18, 0x30, 0x0b, 0x40, 0x4e, 0x31, 0x3f, 0xca, 0xea, 0x8b, 0x53, 0x1b, 0x24, 0xf4, 0x4f, 0xf1, 0x45, 0x13, 0x68, 0xee, 0xa2, 0x01, 0x8c, 0x89, 0xf7, 0x87, 0xf3, 0x9c, 0x0a, 0x52, 0xb8, 0x5b, 0x08, 0x09, 0x2f, 0xd4, 0x75, 0xc2, 0x85, 0xb9, 0x99, 0x33, 0xca, 0xaa, 0x30, 0xe1, 0x06, 0xe4, 0x3b, 0xd1, 0x29, 0xa9, 0xc6, 0x57, 0x98, 0xa1, 0xba, 0x5c, 0x06, 0x68, 0x0e, 0x42, 0xf3, 0x10, 0x4d, 0xd9, 0x33, 0x6e, 0x18 }
	out := Decode(t2)
	out.Dump(0)
}