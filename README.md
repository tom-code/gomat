# gomat
This is attempt to light bulb using matter protocol.

### status of code
- prototyping phase
- it can commission device and send commands to it
- commisioning does not implement any non-required steps (device authenticity verification, attestation, ...). it is minimal code to make it work without any focus on security

### general info
- it is best to understand matter to use this, but here is most important info:
  - device ownership is driven using certificates
  - easiest way how to talk to device is to have signed certificate of device admin user
  - certificates are signed by CA
  - during commissioning procedure root CA certificate is pushed to device together with id of device admin user
  - root CA certificate is something you need to create once and store. loosing CA keys usually means that you will have to commistion devices again
  - to talk to device you have to commission it first
    - to commision device you usually need its pin/passcode and device be in state open for commisioning
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
  - discover command can be used to discover matter devices and their ip address
- find device commissioning passcode/pin
  - device may show it
  - it can be extracted from QR code. use decode-qr to extract passcode from text representation of QR code
  - it can be extracted from manual pairing code. use command decode-mc to extract passcode from manual pairing code
- perform commissioning of device. This authenticates using passcode, uploads CA certificate to device, signs and uploads device's own certificate and sets admin user id.
  - required for commisioning:
    - ip address of device
    - device commissioning passcode/pin
    - ca key and certificate
    - controller node key and certificate
  - example: `./gomat commission --ip 192.168.5.178 --pin 123456 --controller-id 100 --device-id 500`
- light on!
  `./gomat cmd on --ip 192.168.5.178 --controller-id 100 --device-id 500`


### how to use api
create ca with root certificate, create admin user, then commision device:
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
	gomat.Commision(fabric, net.ParseIP(device_ip), pin, admin_user, device_id)
}
```

#### certificate manager
NewFabric function accepts certificate manager object as input parameter. Certificate manager must implement interface CertificateManager and user can supply own implementation. Supplied CertManager created by NewFileCertManager is very simple and stores all data in .pem files under pem directory.