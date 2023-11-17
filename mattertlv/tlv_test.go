package mattertlv

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestBasicEmptyAnonStruct(t *testing.T) {
	var encoder TLVBuffer

	encoder.WriteAnonStruct()
	encoder.WriteStructEnd()

	encoded := encoder.Bytes()
	if hex.EncodeToString(encoded) != "1518" {
		t.Fatalf("incorrect %s", hex.EncodeToString(encoded))
	}

	decoded := Decode(encoded)
	if len(decoded.GetChild()) != 0 {
		t.Fatalf("empty struct test failed")
	}
}

func TestBasic(t *testing.T) {
	var encoder TLVBuffer

	encoder.WriteAnonStruct()
	encoder.WriteUInt8(10, 0x12)
	encoder.WriteUInt16(11, 0x1234)
	encoder.WriteUInt32(12, 0x12345678)
	encoder.WriteUInt64(13, 0x123456789abcdef0)
	encoder.WriteUInt64(14, 0xf23456789abcdef0)
	encoder.WriteOctetString(15, []byte{1,2,3,4,5})
	encoder.WriteBool(16, false)
	encoder.WriteBool(17, true)
	encoder.WriteStructEnd()

	encoded := encoder.Bytes()

	decoded := Decode(encoded)
	if len(decoded.GetChild()) != 8 {
		t.Fatalf("empty struct test failed")
	}

	if hex.EncodeToString(encoded) != "15240a12250b3412260c78563412270df0debc9a78563412270ef0debc9a785634f2300f0501020304052810291118" {
		t.Fatalf("incorrect encoding")
	}

	if decoded.GetItemWithTag(10).GetInt() != 0x12 {
		t.Fatalf("incorrect encoding 10")
	}
	if decoded.GetItemWithTag(11).GetInt() != 0x1234 {
		t.Fatalf("incorrect encoding 11")
	}
	if decoded.GetItemWithTag(12).GetInt() != 0x12345678 {
		t.Fatalf("incorrect encoding 12")
	}
	if decoded.GetItemWithTag(13).GetInt() != 0x123456789abcdef0 {
		t.Fatalf("incorrect encoding 13")
	}
	if decoded.GetItemWithTag(14).GetUint64() != 0xf23456789abcdef0 {
		t.Fatalf("incorrect encoding 14")
	}
	if hex.EncodeToString(decoded.GetItemWithTag(15).GetOctetString()) != "0102030405" {
		t.Fatalf("incorrect encoding 15")
	}
	if decoded.GetItemWithTag(16).GetBool() {
		t.Fatalf("incorrect encoding 16")
	}
	if !decoded.GetItemWithTag(17).GetBool() {
		t.Fatalf("incorrect encoding 17")
	}
}

func TestRec(t *testing.T) {
	var encoder TLVBuffer

	encoder.WriteAnonStruct()
	encoder.WriteOctetString(1, []byte{1,2,3,4,5})
	encoder.WriteArray(2)
	encoder.WriteAnonStruct()
	encoder.WriteOctetString(2, []byte{1,2,3,4,5})
	encoder.WriteUInt32(3, 33)
	encoder.WriteStructEnd()
	encoder.WriteStructEnd()
	encoder.WriteStructEnd()

	encoded := encoder.Bytes()
	if hex.EncodeToString(encoded) != "1530010501020304053602153002050102030405260321000000181818" {
		fmt.Printf(hex.EncodeToString(encoded))
		t.Fatal("invalid encode")
	}

	decoded := Decode(encoded)

	i, err := decoded.GetIntRec([]int{2,0,3})
	if err != nil {
		t.Fatalf("error %s", err.Error())
	}
	if i != 33 {
		t.Fatal("incorrect value")
	}

	it := decoded.GetItemRec([]int{2,0,3})
	if it == nil {
		t.Fatalf("not found")
	}
	if it.GetInt() != 33 {
		t.Fatal("incorrect value")
	}

	it = decoded.GetItemRec([]int{2,0,2})
	if it == nil {
		t.Fatalf("not found")
	}
	if hex.EncodeToString(it.GetOctetString()) != "0102030405" {
		t.Fatal("incorrect value")
	}

	os := decoded.GetOctetStringRec([]int{2,0,2})
	if hex.EncodeToString(os) != "0102030405" {
		t.Fatal("incorrect value")
	}
}
