package onboarding_payload

import (
	"fmt"
	"strconv"
	"strings"
)


func DecodeManualPairingCode(in string) QrContent {
	in = strings.Replace(in, "-", "", -1)
	fmt.Printf("normalized code: %s\n", in)
	first_group := in[0:1]
	second_group := in[1:6]
	third_group := in[6:10]
	//fourth := in[10:11]
	first, _ := strconv.Atoi(first_group)
	second, _ := strconv.Atoi(second_group)
	third, _ := strconv.Atoi(third_group)
	p := second & 0x3fff + third<<14
	d := (first&3 <<10) + (second>>6)&0x300
	return QrContent{
		Passcode: uint32(p),
		Discriminator4: uint16(d),
	}
}