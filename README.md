# gomat
This is attempt to light bulb using matter protocol.

### status of code
- prototyping phase
- it can commission device and send commands to it
- commisioning does not implement any non-required steps (device authenticity verification, attestation, ...). it is minimal code to make it work without any focus on security

### how to use test application

- create directory to hold keys and certificates `mkdir pem`
- generate CA key and certificate using `gomat ca-bootstrap`
- generate controller key and certificate using `gomat ca-createuser 9`
  - 9 is example node-id of controller
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
  - example: `gomat commission --ip 192.168.5.178 --pin 123456`

