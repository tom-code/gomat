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
	fmt.Printf("tag  %d ", i.Tag)
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
			binary.Read(buf, binary.LittleEndian, tmp)
			current.valueInt = uint64(tmp)
		case 6:
			current.Type = TypeInt
			current.Tag = readByte(buf)
			var tmp uint32
			binary.Read(buf, binary.LittleEndian, tmp)
			current.valueInt = uint64(tmp)
		case 7:
			current.Type = TypeInt
			current.Tag = readByte(buf)
			var tmp uint64
			binary.Read(buf, binary.LittleEndian, tmp)
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
		case 0x15:
			current.Type = TypeList
			if tagctrl == 1 {
				current.Tag = readByte(buf)
			}
			decode(buf, &current)
		case 0x16:
			current.Type = TypeList
			if tagctrl == 1 {
				current.Tag = readByte(buf)
			}
			decode(buf, &current)
		case 0x17:
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