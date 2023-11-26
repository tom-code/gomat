// this is example application which shows hw to:
// create fabric (generate CA certificate)
// commission device (upload certificates to it)
// send commands to device
// devica parameters (ip address and passcode) are hardcoded in main function
// this example assumes that device is in state accepting new commissioning

package main

import (
	"math/rand"
	"net"
	"os"

	"github.com/tom-code/gomat"
	"github.com/tom-code/gomat/mattertlv"
	"github.com/tom-code/gomat/symbols"
)

func bootstrap_ca(fabric_id, admin_user uint64) {
	os.Mkdir("pem", 0700)
	cm := gomat.NewFileCertManager(fabric_id)
	cm.BootstrapCa()
	cm.Load()
	if err := cm.CreateUser(admin_user); err != nil {
		panic(err)
	}
}

func loadFabric(fabric_id uint64) *gomat.Fabric {
	cm := gomat.NewFileCertManager(fabric_id)
	cm.Load()
	return gomat.NewFabric(fabric_id, cm)
}

func commission(fabric_id, admin_user, device_id uint64, device_ip string, pin int) {
	fabric := loadFabric(fabric_id)
	if err := gomat.Commission(fabric, net.ParseIP(device_ip), pin, admin_user, device_id); err != nil {
		panic(err)
	}
}

func sendOnCommand(secure_channel *gomat.SecureChannel) {
	on_command := gomat.EncodeIMInvokeRequest(
		1,                           // endpoint
		symbols.CLUSTER_ID_OnOff,    // api cluster (on/off)
		symbols.COMMAND_ID_OnOff_On, // on command
		[]byte{},                    // no extra data
		false, uint16(rand.Uint32()))

	secure_channel.Send(on_command)

	// process ON command response
	response, err := secure_channel.Receive()
	if err != nil {
		panic(err)
	}
	if response.ProtocolHeader.Opcode != gomat.INTERACTION_OPCODE_INVOKE_RSP {
		panic("unexpected message")
	}
	if gomat.ParseImInvokeResponse(&response.Tlv) != 0 {
		response.Tlv.Dump(0)
		panic("response was not OK")
	}
}

func sendColorCommand(secure_channel *gomat.SecureChannel) {
	var tlv mattertlv.TLVBuffer
	tlv.WriteUInt8(0, 100) // hue
	tlv.WriteUInt8(1, 200) // saturation
	tlv.WriteUInt8(2, 10)  // time
	color_command := gomat.EncodeIMInvokeRequest(
		1,                               // endpoint
		symbols.CLUSTER_ID_ColorControl, // color control cluster
		symbols.COMMAND_ID_ColorControl_MoveToHueAndSaturation,
		tlv.Bytes(),
		false, uint16(rand.Uint32()))

	secure_channel.Send(color_command)

	// process command response
	response, err := secure_channel.Receive()
	if err != nil {
		panic(err)
	}
	if response.ProtocolHeader.Opcode != gomat.INTERACTION_OPCODE_INVOKE_RSP {
		panic("unexpected message")
	}
	if gomat.ParseImInvokeResponse(&response.Tlv) != 0 {
		response.Tlv.Dump(0)
		panic("response was not OK")
	}
}

func main() {
	var fabric_id uint64 = 0x100
	var admin_user uint64 = 5
	var device_id uint64 = 10
	device_ip := "192.168.5.178"
	pin := 123456

	// Generate CA keys/certificate + admin user
	// do this only once for your fabric
	bootstrap_ca(fabric_id, admin_user)

	// Commission device - upload certificates + set admin user
	// do this once for device (per fabric)
	commission(fabric_id, admin_user, device_id, device_ip, pin)

	// connect to commissioned device
	fabric := loadFabric(fabric_id)
	secure_channel, err := gomat.ConnectDevice(net.ParseIP(device_ip), 5540, fabric, device_id, admin_user)
	if err != nil {
		panic(err)
	}
	defer secure_channel.Close()

	// send ON command
	sendOnCommand(&secure_channel)

	// send set color command
	sendColorCommand(&secure_channel)
}
