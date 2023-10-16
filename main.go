package main

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"gomat/ca"
	"gomat/tlvdec"
	"io"
	"log"
	"net"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/hkdf"
)


func make_nonce3(counter uint32, node []byte) []byte{
	var n bytes.Buffer
	n.WriteByte(0)
	binary.Write(&n, binary.LittleEndian, counter)
	n.Write(node)
	return n.Bytes()
}


type Channel struct {
	udp net.PacketConn
	remote_address net.UDPAddr
	out_counter uint32
}

func NewChannel(remote_ip net.IP, remote_port, local_port int) Channel {
	var out Channel
	out.remote_address = net.UDPAddr{
		IP : remote_ip,
		Port: remote_port,
	}
	var err error
	out.udp, err = net.ListenPacket("udp", fmt.Sprintf(":%d", local_port))
	if err != nil {
		panic(err)
	}
	out.out_counter = 1
	return out
}

func (ch *Channel)send(data []byte) {
	ch.udp.WriteTo(data, &ch.remote_address)
}
func (ch *Channel)receive() ([]byte, error) {
	buf := make([]byte, 1024)
	n, _, errx := ch.udp.ReadFrom(buf)
	if errx != nil {
		panic(errx)
	}
	return buf[:n], nil
}


type SecureChannel struct {
	udp *Channel
	encrypt_key []byte
	decrypt_key []byte
	remote_node []byte
	local_node []byte
	counter uint32
	session int
}

func (sc *SecureChannel) receive() DecodedGeneric {
	data, _ := sc.udp.receive()
	decode_buffer := bytes.NewBuffer(data)
	var out DecodedGeneric
	out.msg.decodeBase(decode_buffer)
	add := data[:len(data)-decode_buffer.Len()]
	proto := decode_buffer.Bytes()


	if len(sc.decrypt_key) > 0 {
		nonce := make_nonce3(out.msg.messageCounter, sc.remote_node)
		c, err := aes.NewCipher(sc.decrypt_key)
		if err != nil {
			panic(err)
		}
		ccm, err := NewCCMWithNonceAndTagSizes(c, len(nonce), 16)
		if err != nil {
			panic(err)
		}
		ciphertext := proto
		decbuf := []byte{}
		outx, err := ccm.Open(decbuf, nonce, ciphertext, add)
		if err != nil {
			panic(err)
		}

		decoder := bytes.NewBuffer(outx)

		out.proto.decode(decoder)
		if len(decoder.Bytes()) > 0 {
			tlvdata := make([]byte, decoder.Len())
			n, _ := decoder.Read(tlvdata)
			out.payload = tlvdata[:n]
		}
	} else {
		out.proto.decode(decode_buffer)
		if len(decode_buffer.Bytes()) > 0 {
			tlvdata := make([]byte, decode_buffer.Len())
			n, _ := decode_buffer.Read(tlvdata)
			out.payload = tlvdata[:n]
		}
	}

	if out.proto.protocolId == 0 {
		if out.proto.opcode == 0x10 {  // standalone ack
			return sc.receive()
		}
	}

	ack := AckGen(out.proto, out.msg.messageCounter)
	sc.send(ack)

	if out.proto.protocolId == 0 {
		if out.proto.opcode == 0x40 {  // status report
			return out
		}
	}
	if len(out.payload) > 0 {
		out.tlv = tlvdec.Decode(out.payload)
	}
	return out
}

func (sc *SecureChannel)send(data []byte) {

	sc.counter = sc.counter + 1
	var buffer bytes.Buffer
	msg := Message {
		sessionId: uint16(sc.session),
		securityFlags: 0,
		messageCounter: sc.counter,
		sourceNodeId: []byte{1,2,3,4,5,6,7,8},
	}
	msg.encodeBase(&buffer)
	if len(sc.encrypt_key) == 0 {
		buffer.Write(data)
	} else {

		header_slice := buffer.Bytes()
		add2 := make([]byte, len(header_slice))
		copy(add2, header_slice)

		nonce := make_nonce3(sc.counter, sc.local_node)

		c, err := aes.NewCipher(sc.encrypt_key)
		if err != nil {
			panic(err)
		}
		ccm, err := NewCCMWithNonceAndTagSizes(c, len(nonce), 16)
		if err != nil {
			panic(err)
		}
		CipherText := ccm.Seal(nil, nonce, data, add2)
		buffer.Write(CipherText)
	}


	sc.udp.send(buffer.Bytes())
}


func do_spake2p(pin int, udp *Channel) SecureChannel {
	secure_channel := SecureChannel {
		udp: udp,
		session: 0,
	}

	pbkdf_request := PBKDFParamRequest()
	secure_channel.send(pbkdf_request)

	pbkdf_responseS := secure_channel.receive()
	pbkdf_response_salt := pbkdf_responseS.tlv.GetOctetStringRec([]int{4,2})
	pbkdf_response_iterations := pbkdf_responseS.tlv.GetIntRec([]int{4,1})
	pbkdf_response_session := pbkdf_responseS.tlv.GetIntRec([]int{3})



	sctx := newSpaceCtx()
	sctx.gen_w(pin, pbkdf_response_salt, int(pbkdf_response_iterations))
	sctx.gen_random_X()
	sctx.calc_X()

	pake1 := Pake1ParamRequest(sctx.X.as_bytes())
	secure_channel.send(pake1)

	pake2s := secure_channel.receive()
	pake2s.tlv.Dump(1)
	pake2_pb := pake2s.tlv.GetOctetStringRec([]int{1})


	sctx.Y.from_bytes(pake2_pb)
	sctx.calc_ZV()
	ttseed := []byte("CHIP PAKE V1 Commissioning")
	ttseed = append(ttseed, pbkdf_request[6:]...) // 6 is size of proto header
	ttseed = append(ttseed, pbkdf_responseS.payload...)
	sctx.calc_hash(ttseed)

	pake3 := Pake3ParamRequest(sctx.cA)
	secure_channel.send(pake3)


	/*status_report :=*/ secure_channel.receive()

	secure_channel = SecureChannel {
		udp: udp,
		decrypt_key: sctx.decrypt_key,
		encrypt_key: sctx.encrypt_key,
		remote_node: []byte{0,0,0,0,0,0,0,0},
		local_node: []byte{0,0,0,0,0,0,0,0},
		session: int(pbkdf_response_session),
	}

	return secure_channel
}

func do_sigma(fabric *Fabric, secure_channel SecureChannel) SecureChannel {

	controller_privkey, _ := ecdh.P256().GenerateKey(rand.Reader)
	sigma_context := SigmaContext {
		session_privkey: controller_privkey,
	}
	sigma_context.genSigma1(fabric)
	sigma1 := genSigma1Req2(sigma_context.sigma1payload)
	secure_channel.send(sigma1)


	sigma_context.sigma2dec = secure_channel.receive()

	sigma_context.controller_key = fabric.certificateManager.get_privkey("ctrl")
	sigma_context.controller_matter_certificate = MatterCert2(fabric, fabric.certificateManager.get_certificate("ctrl"))

	to_send := sigma_context.sigma3(fabric)
	secure_channel.send(to_send)

	/*respx :=*/ secure_channel.receive()

	secure_channel.decrypt_key = sigma_context.r2ikey
	secure_channel.encrypt_key = sigma_context.i2rkey
	secure_channel.remote_node = []byte{2,0,0,0,0,0,0,0}
	secure_channel.local_node = []byte{9,0,0,0,0,0,0,0}
	secure_channel.session = sigma_context.session
	return secure_channel
}


func filter_devices(devices []Device, qr QrContent) Device {
	for _, device := range(devices) {
		log.Printf("%s %d\n", device.D, qr.discriminator)
		if device.D != fmt.Sprintf("%d", qr.discriminator) {
			continue
		}
		if device.VendorId != int(qr.vendor) {
			continue
		}
		if device.ProductId != int(qr.product) {
			continue
		}
		return device
	}
	panic("not foind")
}

func discover_with_qr(qr string) Device {
	var devices []Device
	var err error
	for i:=0; i<5; i++ {
		devices, err = discover("en0")
		if err != nil {
			panic(err)
		}
		if len(devices) > 0 {
			break
		}

	}
	device := filter_devices(devices, decode_qr_text(qr))
	return device
}

func commision(fabric *Fabric, device Device) {

	/*
	var devices []Device
	var err error
	for i:=0; i<5; i++ {
		devices, err = discover("en0")
		if err != nil {
			panic(err)
		}
		if len(devices) > 0 {
			break
		}

	}
	device := filter_devices(devices, decode_qr_text("MT:-24J0AFN00SIQ663000"))
	device.Dump()
*/
	channel := NewChannel(device.addrs[1], 5540, 55555)
	secure_channel := SecureChannel {
		udp: &channel,
	}

	secure_channel = do_spake2p(123456, &channel)

	// send csr request
	var tlv TLVBuffer
	tlv.writeOctetString(0, create_random_bytes(32))
	to_send := invokeCommand2(0, 0x3e, 4, tlv.data.Bytes())
	secure_channel.send(to_send)



	log.Println("--------------------------------------------------")
	csr_resp := secure_channel.receive()


	nocsr := csr_resp.tlv.GetOctetStringRec([]int{1,0,0,1,0})
	tlv2 := tlvdec.Decode(nocsr)
	csr := tlv2.GetOctetStringRec([]int{1})
	csrp, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		panic(err)
	}


	//AddTrustedRootCertificate
	var tlv4 TLVBuffer
	tlv4.writeOctetString(0, MatterCert2(fabric, fabric.certificateManager.ca_certificate))
	to_send = invokeCommand2(0, 0x3e, 0xb, tlv4.data.Bytes())
	secure_channel.send(to_send)


	/*ds :=*/ secure_channel.receive()


	//noc_x509 := sign_cert(csrp, 2, "user")
	noc_x509 := fabric.certificateManager.sign_cert(csrp.PublicKey.(*ecdsa.PublicKey), 2, "device")
	noc_matter := MatterCert2(fabric, noc_x509)
	//AddNOC
	var tlv5 TLVBuffer
	tlv5.writeOctetString(0, noc_matter)
	tlv5.writeOctetString(2, []byte{0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf}) //ipk
	tlv5.writeUInt(3, TYPE_UINT_2, 9)   // admin subject !
	tlv5.writeUInt(4, TYPE_UINT_2, 101) // admin vendorid ??
	to_send = invokeCommand2(0, 0x3e, 0x6, tlv5.data.Bytes())

	secure_channel.send(to_send)

	/*ds =*/ secure_channel.receive()

	secure_channel.decrypt_key = []byte{}
	secure_channel.encrypt_key = []byte{}
	secure_channel.session = 0

	secure_channel = do_sigma(fabric, secure_channel)


	//commissioning complete
	to_send = invokeCommand2(0, 0x30, 4, []byte{})
	secure_channel.send(to_send)


	/*respx =*/ secure_channel.receive()


	//LIGHT ON!!!!!!!!!!!!!!!!!!!!!
	// cluster=6 on/off - command 1=on
	to_send = invokeCommand2(1, 6, 1, []byte{})
	secure_channel.send(to_send)

	light_resp := secure_channel.receive()
	light_resp.tlv.Dump(0)

	//r1 := invokeRead(0, 0x28, 1)
	//secure_channel.send(uint16(sigma2responder_session), r1)
	//resp := secure_channel.receive()
	//resp.tlv.Dump(0)

	r1 := invokeRead(0, 0x1d, 0)
	secure_channel.send(r1)
	resp := secure_channel.receive()
	resp.tlv.Dump(0)
}

func light_off(fabric *Fabric, device Device) {

	channel := NewChannel(device.addrs[1], 5540, 55555)
	secure_channel := SecureChannel {
		udp: &channel,
		counter: 500,
	}
	secure_channel = do_sigma(fabric, secure_channel)

	to_send := invokeCommand2(1, 6, 0, []byte{})
	secure_channel.send(to_send)

	light_resp := secure_channel.receive()
	light_resp.tlv.Dump(0)
}

type Fabric struct {
	id uint64
	certificateManager *CertManager
}

func (fabric Fabric) compressedFabric() []byte {
	capub := fabric.certificateManager.ca_private_key.PublicKey
	capublic_key := elliptic.Marshal(elliptic.P256(), capub.X, capub.Y)

	hkdfz := hkdf.New(sha256.New, capublic_key[1:], []byte{0,0,0,0,0,0,0,0x10}, []byte("CompressedFabric"))
	key := make([]byte, 8)
	if _, err := io.ReadFull(hkdfz, key); err != nil {
		panic(err)
	}
	//log.Printf("compressed fabric: %s\n", hex.EncodeToString(key))
	return key
}
func (fabric Fabric) make_ipk() []byte {
	ipk := []byte{0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf}
	hkdfz := hkdf.New(sha256.New, ipk, fabric.compressedFabric(), []byte("GroupKey v1.0"))
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdfz, key); err != nil {
		panic(err)
	}
	return key
}

//var certificate_manager *CertManager
func newFabric() *Fabric {
	out:= &Fabric{
		id: 0x10,
		certificateManager: NewCertManager(),
	}
	out.certificateManager.load()
	return out
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "mama",
		Short: "matter manager",
	}
	var flowCmd = &cobra.Command{
		Use:   "commision",
		Run: func(cmd *cobra.Command, args []string) {
			qr, _ := cmd.Flags().GetString("qr")
			fabric := newFabric()
			commision(fabric, discover_with_qr(qr))
		},
	}
	flowCmd.Flags().StringP("qr", "q", "", "qr text")
	var flow2Cmd = &cobra.Command{
		Use:   "light_off",
		Run: func(cmd *cobra.Command, args []string) {
		  qr, _ := cmd.Flags().GetString("qr")
		  fabric := newFabric()
		  light_off(fabric, discover_with_qr(qr))
		},
	}
	flow2Cmd.Flags().StringP("qr", "q", "", "qr text")
	var cakeygenCmd = &cobra.Command{
		Use:   "ca-keygen",
		Run: func(cmd *cobra.Command, args []string) {
		  ca.Create_ca_cert()
		},
	}
	var cacreateuserCmd = &cobra.Command{
		Use:   "ca-createuser",
		Run: func(cmd *cobra.Command, args []string) {
		  cm := NewCertManager()
		  cm.load()
		  cm.create_user(9, "ctrl")
		},
	}
	var cabootCmd = &cobra.Command{
		Use:   "ca-bootstrap",
		Run: func(cmd *cobra.Command, args []string) {
		  bootstrap_ca()
		  NewCertManager().load()
		},
	}
	var testCmd = &cobra.Command{
		Use:   "test",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	var discoverCmd = &cobra.Command{
		Use:   "discover",
		Run: func(cmd *cobra.Command, args []string) {
			devices, err := discover("en0")
			if err != nil {
				panic(err)
			}
			for _, device := range devices {
				device.Dump()
			}


		},
	}
	rootCmd.AddCommand(cacreateuserCmd)
	rootCmd.AddCommand(cabootCmd)
	rootCmd.AddCommand(flowCmd)
	rootCmd.AddCommand(flow2Cmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(cakeygenCmd)
	rootCmd.AddCommand(discoverCmd)
	rootCmd.Execute()
}
