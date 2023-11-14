# gomat
Simple matter protocol library

![go build](https://github.com/tom-code/gomat/actions/workflows/go.yml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/tom-code/gomat)](https://goreportcard.com/report/github.com/tom-code/gomat)

### goal of project
The goal is to create golang library and supporting tools to access matter devices.

### status of project
- it can commission devices and send commands to them
- commissioning does not implement any non-mandatory steps (device authenticity verification, attestation, ...). it is minimal code to make it work without any focus on security


#### tested devices
- tested against virtual devices which are part of reference implementation https://github.com/project-chip/connectedhomeip
- tested with yeelight cube
  - can control all leds at same time on/off/color, ...
  - I was not able to determine how to control individual leds. There seems to be proprietary interface on endpoint 2 and I was unable to find any documentation of it.

### general info
- it is best to understand matter to use this, but here is most important info:
  - device access is managed using certificates
  - easiest way how to talk to device is to have signed certificate of device admin user (alternative is setup ACLs and use non-admin user)
  - certificates are signed by CA
  - during commissioning procedure root CA certificate is pushed to device together with id of device admin user
  - root CA certificate is something you need to create once and store. loosing CA keys usually means that you will have to commission devices again
  - to talk to device you have to commission it first
    - to commission device you usually need its pin/passcode and device be in state open for commisioning
    - device gets into commisioning window open state often by "factory reset"
    - when device is commissioned - connected to some fabric, it can be commissionined into other fabrics using api, where existing admin user sets device to be open for additional commissioning. During that device can be connected to additional fabric(s) - additional root CA installed and additional admin user configured

### how to use test application
- compile
  `go build -o gomat github.com/tom-code/gomat/demo`

- create directory to hold keys and certificates `mkdir pem`
- generate CA key and certificate using `./gomat ca-bootstrap`
- generate controller key and certificate using `./gomat ca-createuser 100`
  - 100 is example node-id of controller
- find device IP
  - discover command can be used to discover matter devices and their ip address `./gomat discover commissionable -d`
- find device commissioning passcode/pin
  - device may show it
  - it can be extracted from QR code. use decode-qr to extract passcode from text representation of QR code `./gomat decode-qr MT:-24J0AFN00SIQ663000`
  - it can be extracted from manual pairing code. use command decode-mc to extract passcode from manual pairing code `./gomat decode-mc 35792000079`
- perform commissioning of device. This authenticates using passcode, uploads CA certificate to device, signs and uploads device's own certificate and sets admin user id.
  - required for commisioning:
    - ip address of device
    - device commissioning passcode/pin
    - ca key and certificate
    - controller node key and certificate
  - example: `./gomat commission --ip 192.168.5.178 --pin 123456 --controller-id 100 --device-id 500`
- light on!
  `./gomat cmd on --ip 192.168.5.178 --controller-id 100 --device-id 500`
- set color hue=150 saturation=200 transition_time=10
  `./gomat cmd color --ip 192.168.5.220 --controller-id 100 --device-id 500 150 200 10`


### how to use api
#### commission device using api
create ca with root certificate, create admin user, then commission device:
```
package main

import (
  "net"

  "github.com/tom-code/gomat"
)


func main() {
  var fabric_id uint64 = 0x100
  var admin_user uint64 = 5
  var device_id uint64 = 10
  device_ip := "192.168.5.178"
  pin := 123456

  cm := gomat.NewFileCertManager(fabric_id)
  cm.BootstrapCa()
  cm.Load()
  cm.CreateUser(admin_user)
  fabric := gomat.NewFabric(fabric_id, cm)
  gomat.Commission(fabric, net.ParseIP(device_ip), pin, admin_user, device_id)
}
```

#### send ON command to commissioned device using api
```
package main

import (
  "net"

  "github.com/tom-code/gomat"
)


func main() {
  var fabric_id uint64 = 0x100
  var admin_user uint64 = 5
  var device_id uint64 = 10
  device_ip := "192.168.5.178"

  cm := gomat.NewFileCertManager(fabric_id)
  cm.Load()
  fabric := gomat.NewFabric(fabric_id, cm)

  secure_channel, err := gomat.StartSecureChannel(net.ParseIP(device_ip), 5540, 55555)
  if err != nil {
    panic(err)
  }
  defer secure_channel.Close()
  secure_channel, err = gomat.SigmaExchange(fabric, admin_user, device_id, secure_channel)
  if err != nil {
    panic(err)
  }

  on_command := gomat.EncodeInvokeCommand(1,        // endpoint
                                          6,        // api cluster (on/off)
                                          1,        // on command
                                          []byte{}, // no extra data
                                          )
  secure_channel.Send(on_command)
  resp, err := secure_channel.Receive()
  if err != nil {
    panic(err)
  }
  resp.Tlv.Dump(0)
}
```

#### discover IP address of previously commissioned device using api
Device exposes its info using mdns under identifier [compressed-fabric-id]-[device-id].
For this reason to discover commissioned device fabric info is required.
```
package main

import (
  "encoding/hex"
  "fmt"
  "strings"

  "github.com/tom-code/gomat"
  "github.com/tom-code/gomat/discover"
)



func main() {
  var fabric_id uint64 = 0x100
  var device_id uint64 = 10


  cm := gomat.NewFileCertManager(fabric_id)
  cm.Load()
  fabric := gomat.NewFabric(fabric_id, cm)

  identifier := fmt.Sprintf("%s-%016X", hex.EncodeToString(fabric.CompressedFabric()), device_id)
  identifier = strings.ToUpper(identifier)
  identifier = identifier + "._matter._tcp.local."
  fmt.Printf("%s\n", identifier)
  devices := discover.DiscoverComissioned("", true, identifier)
  for _, d := range devices {
    fmt.Printf("host:%s ip:%v\n", d.Host, d.Addrs)
  }
}
```

#### extract pairing passcode from QR code and manual pairing code
Following example shows how to extract passcode from textual representation of QR code or from manual pairing code.
Manual pairing code can have dash characters at any position(they are discarded)
```
package main

import (
	"fmt"

	"github.com/tom-code/gomat/onboarding_payload"
)


func main() {
	setup_qr_code := "MT:-24J0AFN00SIQ663000"
	qr_decoded := onboarding_payload.DecodeQrText(setup_qr_code)
	fmt.Printf("passcode: %d\n", qr_decoded.Passcode)


	manual_pair_code := "357-920-000-79"
	code_decoded := onboarding_payload.DecodeManualPairingCode(manual_pair_code)
	fmt.Printf("passcode: %d\n", code_decoded.Passcode)
}

```

#### Set color of light to specific hue color
```
package main

import (
	"fmt"
	"net"

	"github.com/tom-code/gomat"
	"github.com/tom-code/gomat/mattertlv"
)


func main() {
	var fabric_id uint64 = 0x100
	var admin_user uint64 = 5
	var device_id uint64 = 10
	device_ip := "192.168.5.178"

	cm := gomat.NewFileCertManager(fabric_id)
	cm.Load()
	fabric := gomat.NewFabric(fabric_id, cm)


	secure_channel, err := gomat.StartSecureChannel(net.ParseIP(device_ip), 5540, 55555)
	if err != nil {
		panic(err)
	}
	defer secure_channel.Close()
	secure_channel, err = gomat.SigmaExchange(fabric, admin_user, device_id, secure_channel)
	if err != nil {
		panic(err)
	}

	var tlv mattertlv.TLVBuffer
	tlv.WriteUInt8(0, byte(hue))        // hue
	tlv.WriteUInt8(1, byte(saturation)) // saturation
	tlv.WriteUInt8(2, byte(time))       // time
	to_send := gomat.EncodeInvokeCommand(1, 0x300, 6, tlv.Bytes())
	secure_channel.Send(to_send)

	resp, err := secure_channel.Receive()
	if err != nil {
		panic(err)
	}
	status, err := resp.Tlv.GetIntRec([]int{1,0,1,1,0})
	if err != nil {
		panic(err)
	}
	fmt.Printf("result status: %d\n", status)
}
```


#### certificate manager
NewFabric function accepts certificate manager object as input parameter. Certificate manager must implement interface CertificateManager and user can supply own implementation. Supplied CertManager created by NewFileCertManager is very simple and stores all data in .pem files under pem directory.
