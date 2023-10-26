package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"gomat/tlvdec"
	"gomat/tlvenc"
	"log"
	randm "math/rand"
	"net"
	"strconv"

	"github.com/spf13/cobra"
)


func do_spake2p(pin int, udp *Channel) SecureChannel {
	exchange := uint16(randm.Intn(0xffff))
	secure_channel := SecureChannel {
		udp: udp,
		session: 0,
	}

	pbkdf_request := PBKDFParamRequest(exchange)
	secure_channel.send(pbkdf_request)

	pbkdf_responseS := secure_channel.receive()
	if pbkdf_responseS.proto.opcode != SEC_CHAN_OPCODE_PBKDF_RESP {
		panic("SEC_CHAN_OPCODE_PBKDF_RESP not received")
	}
	pbkdf_response_salt := pbkdf_responseS.tlv.GetOctetStringRec([]int{4,2})
	pbkdf_response_iterations, err := pbkdf_responseS.tlv.GetIntRec([]int{4,1})
	if err != nil {
		panic("can't get pbkdf_response_iterations")
	}
	pbkdf_response_session, err := pbkdf_responseS.tlv.GetIntRec([]int{3})
	if err != nil {
		panic("can't get pbkdf_response_session")
	}


	sctx := newSpaceCtx()
	sctx.gen_w(pin, pbkdf_response_salt, int(pbkdf_response_iterations))
	sctx.gen_random_X()
	sctx.calc_X()

	pake1 := Pake1ParamRequest(exchange, sctx.X.as_bytes())
	secure_channel.send(pake1)

	pake2s := secure_channel.receive()
	if pake2s.proto.opcode != SEC_CHAN_OPCODE_PAKE2 {
		panic("SEC_CHAN_OPCODE_PAKE2 not received")
	}
	//pake2s.tlv.Dump(1)
	pake2_pb := pake2s.tlv.GetOctetStringRec([]int{1})


	sctx.Y.from_bytes(pake2_pb)
	sctx.calc_ZV()
	ttseed := []byte("CHIP PAKE V1 Commissioning")
	ttseed = append(ttseed, pbkdf_request[6:]...) // 6 is size of proto header
	ttseed = append(ttseed, pbkdf_responseS.payload...)
	sctx.calc_hash(ttseed)

	pake3 := Pake3ParamRequest(exchange, sctx.cA)
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

func do_sigma(fabric *Fabric, controller_id uint64, device_id uint64, secure_channel SecureChannel) SecureChannel {

	controller_privkey, _ := ecdh.P256().GenerateKey(rand.Reader)
	sigma_context := SigmaContext {
		session_privkey: controller_privkey,
		exchange: uint16(randm.Intn(0xffff)),
	}
	sigma_context.genSigma1(fabric, device_id)
	sigma1 := genSigma1Req2(sigma_context.sigma1payload, sigma_context.exchange)
	secure_channel.send(sigma1)


	sigma_context.sigma2dec = secure_channel.receive()
	if sigma_context.sigma2dec.proto.opcode != 0x31 {
		panic("sigma2 not received")
	}

	sigma_context.controller_key = fabric.certificateManager.GetPrivkey(controller_id)
	sigma_context.controller_matter_certificate = MatterCert2(fabric, fabric.certificateManager.GetCertificate(controller_id))

	to_send := sigma_context.sigma3(fabric)
	secure_channel.send(to_send)

	/*respx :=*/ secure_channel.receive()

	secure_channel.decrypt_key = sigma_context.r2ikey
	secure_channel.encrypt_key = sigma_context.i2rkey
	secure_channel.remote_node = id_to_bytes(device_id)
	secure_channel.local_node = id_to_bytes(controller_id)
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

func commision(fabric *Fabric, device_ip net.IP, pin int, controller_id, device_id uint64) {

	channel := NewChannel(device_ip, 5540, 55555)
	secure_channel := SecureChannel {
		udp: &channel,
	}

	secure_channel = do_spake2p(pin, &channel)

	// send csr request
	var tlv tlvenc.TLVBuffer
	tlv.WriteOctetString(0, create_random_bytes(32))
	to_send := invokeCommand2(0, 0x3e, 4, tlv.Bytes())
	secure_channel.send(to_send)

	csr_resp := secure_channel.receive()

	nocsr := csr_resp.tlv.GetOctetStringRec([]int{1,0,0,1,0})
	tlv2 := tlvdec.Decode(nocsr)
	csr := tlv2.GetOctetStringRec([]int{1})
	csrp, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		panic(err)
	}

	//AddTrustedRootCertificate
	var tlv4 tlvenc.TLVBuffer
	tlv4.WriteOctetString(0, MatterCert2(fabric, fabric.certificateManager.GetCaCertificate()))
	to_send = invokeCommand2(0, 0x3e, 0xb, tlv4.Bytes())
	secure_channel.send(to_send)


	/*ds :=*/ secure_channel.receive()


	//noc_x509 := sign_cert(csrp, 2, "user")
	noc_x509 := fabric.certificateManager.SignCertificate(csrp.PublicKey.(*ecdsa.PublicKey), device_id)
	noc_matter := MatterCert2(fabric, noc_x509)
	//AddNOC
	var tlv5 tlvenc.TLVBuffer
	tlv5.WriteOctetString(0, noc_matter)
	tlv5.WriteOctetString(2, fabric.ipk) //ipk
	tlv5.WriteUInt(3, tlvenc.TYPE_UINT_2, controller_id)   // admin subject !
	tlv5.WriteUInt(4, tlvenc.TYPE_UINT_2, 101) // admin vendorid ??
	to_send = invokeCommand2(0, 0x3e, 0x6, tlv5.Bytes())

	secure_channel.send(to_send)

	/*ds =*/ secure_channel.receive()

	secure_channel.decrypt_key = []byte{}
	secure_channel.encrypt_key = []byte{}
	secure_channel.session = 0

	secure_channel = do_sigma(fabric, controller_id, device_id, secure_channel)


	//commissioning complete
	to_send = invokeCommand2(0, 0x30, 4, []byte{})
	secure_channel.send(to_send)


	respx := secure_channel.receive()
	commisioning_result, err := respx.tlv.GetIntRec([]int{1, 0, 0, 1, 0})
	if err != nil {
		panic(err)
	}
	if commisioning_result == 0 {
		log.Printf("commissioning OK\n")
	} else {
		log.Printf("commissioning error: %d\n", commisioning_result)
	}
}

func command_off(fabric *Fabric, ip net.IP, controller_id, device_id uint64) {

	channel := NewChannel(ip, 5540, 55555)
	secure_channel := SecureChannel {
		udp: &channel,
		counter: uint32(randm.Intn(0xffffffff)),
	}
	secure_channel = do_sigma(fabric, controller_id, device_id, secure_channel)

	to_send := invokeCommand2(1, 6, 0, []byte{})
	secure_channel.send(to_send)

	resp := secure_channel.receive()
	status, err := resp.tlv.GetIntRec([]int{1,0,1,1,0})
	if err != nil {
		panic(err)
	}
	fmt.Printf("result status: %d\n", status)
}


func command_on(fabric *Fabric, ip net.IP, controller_id, device_id uint64) {

	channel := NewChannel(ip, 5540, 55555)
	secure_channel := SecureChannel {
		udp: &channel,
		counter: uint32(randm.Intn(0xffffffff)),
	}
	secure_channel = do_sigma(fabric, controller_id, device_id, secure_channel)

	to_send := invokeCommand2(1, 6, 1, []byte{})
	secure_channel.send(to_send)

	resp := secure_channel.receive()
	status, err := resp.tlv.GetIntRec([]int{1,0,1,1,0})
	if err != nil {
		panic(err)
	}
	fmt.Printf("result status: %d\n", status)
}

func command_list_fabrics(fabric *Fabric, ip net.IP, controller_id, device_id uint64) {

	channel := NewChannel(ip, 5540, 55555)
	secure_channel := SecureChannel {
		udp: &channel,
		counter: uint32(randm.Intn(0xffffffff)),
	}
	secure_channel = do_sigma(fabric, controller_id, device_id, secure_channel)

	to_send := invokeRead(0, 0x3e, 1)
	secure_channel.send(to_send)

	resp := secure_channel.receive()
	resp.tlv.Dump(0)
}

func command_generic_read(fabric *Fabric, ip net.IP, controller_id, device_id uint64, endpoint, cluster, attr byte) {

	channel := NewChannel(ip, 5540, 55555)
	secure_channel := SecureChannel {
		udp: &channel,
		counter: uint32(randm.Intn(0xffffffff)),
	}
	secure_channel = do_sigma(fabric, controller_id, device_id, secure_channel)

	to_send := invokeRead(endpoint, cluster, attr)
	secure_channel.send(to_send)

	resp := secure_channel.receive()
	resp.tlv.Dump(0)
}


func main() {
	var rootCmd = &cobra.Command{
		Use:   "gomat",
		Short: "matter manager",
	}
	var commissionCmd = &cobra.Command{
		Use:   "commission",
		Run: func(cmd *cobra.Command, args []string) {
			ip, _ := cmd.Flags().GetString("ip")
			if len(ip) == 0 {
				panic("ip address is required")
			}
			pin, _ := cmd.Flags().GetString("pin")
			if len(pin) == 0 {
				panic("passcode is required")
			}
			fabric := newFabric()
			device_id,_ := cmd.Flags().GetUint64("device-id")
			controller_id,_ := cmd.Flags().GetUint64("controller-id")
			pinn, err := strconv.Atoi(pin)
			if err != nil {
				panic(err)
			}
			//commision(fabric, discover_with_qr(qr).addrs[1], 123456)
			commision(fabric, net.ParseIP(ip), pinn, controller_id, device_id)
		},
	}
	commissionCmd.Flags().StringP("ip", "i", "", "ip address")
	commissionCmd.Flags().StringP("pin", "p", "", "pin")
	commissionCmd.Flags().Uint64P("device-id", "", 2, "device id")
	commissionCmd.Flags().Uint64P("controller-id", "", 9, "controller id")
	var offCmd = &cobra.Command{
		Use:   "cmd_off",
		Run: func(cmd *cobra.Command, args []string) {
		  fabric := newFabric()
		  ip, _ := cmd.Flags().GetString("ip")
		  device_id,_ := cmd.Flags().GetUint64("device-id")
		  controller_id,_ := cmd.Flags().GetUint64("controller-id")
		  command_off(fabric, net.ParseIP(ip), controller_id, device_id)
		},
	}
	offCmd.Flags().Uint64P("device-id", "", 2, "device id")
	offCmd.Flags().Uint64P("controller-id", "", 9, "controller id")
	offCmd.Flags().StringP("ip", "i", "", "ip address")
	var onCmd = &cobra.Command{
		Use:   "cmd_on",
		Run: func(cmd *cobra.Command, args []string) {
		  fabric := newFabric()
		  ip, _ := cmd.Flags().GetString("ip")
		  device_id,_ := cmd.Flags().GetUint64("device-id")
		  controller_id,_ := cmd.Flags().GetUint64("controller-id")
		  command_on(fabric, net.ParseIP(ip), controller_id, device_id)
		},
	}
	onCmd.Flags().Uint64P("device-id", "", 2, "device id")
	onCmd.Flags().Uint64P("controller-id", "", 9, "controller id")
	onCmd.Flags().StringP("ip", "i", "", "ip address")

	var list_fabricsCmd = &cobra.Command{
		Use:   "cmd_list_fabrics",
		Run: func(cmd *cobra.Command, args []string) {
		  fabric := newFabric()
		  ip, _ := cmd.Flags().GetString("ip")
		  device_id,_ := cmd.Flags().GetUint64("device-id")
		  controller_id,_ := cmd.Flags().GetUint64("controller-id")
		  command_list_fabrics(fabric, net.ParseIP(ip), controller_id, device_id)
		},
	}
	list_fabricsCmd.Flags().Uint64P("device-id", "", 2, "device id")
	list_fabricsCmd.Flags().Uint64P("controller-id", "", 9, "controller id")
	list_fabricsCmd.Flags().StringP("ip", "i", "", "ip address")

	var readCmd = &cobra.Command{
		Use:   "cmd_read [endpoint] [cluster] [attribute]",
		Run: func(cmd *cobra.Command, args []string) {
		  fabric := newFabric()
		  ip, _ := cmd.Flags().GetString("ip")
		  device_id,_ := cmd.Flags().GetUint64("device-id")
		  controller_id,_ := cmd.Flags().GetUint64("controller-id")
		  endpoint, _ := strconv.ParseInt(args[0], 0, 16)
		  cluster, _ := strconv.ParseInt(args[1], 0, 16)
		  attr, _ := strconv.ParseInt(args[2], 0, 16)
		  command_generic_read(fabric, net.ParseIP(ip), controller_id, device_id, byte(endpoint), byte(cluster), byte(attr))
		},
		Args: cobra.MinimumNArgs(3),
	}
	readCmd.Flags().Uint64P("device-id", "", 2, "device id")
	readCmd.Flags().Uint64P("controller-id", "", 9, "controller id")
	readCmd.Flags().StringP("ip", "i", "", "ip address")

	var cacreateuserCmd = &cobra.Command{
		Use:   "ca-createuser [id]",
		Run: func(cmd *cobra.Command, args []string) {
		  ids := args[0]
		  id, err := strconv.Atoi(ids)
		  if err != nil {
			panic(err)
		  }
		  //cm := NewCertManager(0x99)
		  fabric := newFabric()
		  fabric.certificateManager.Load()
		  fabric.certificateManager.CreateUser(uint64(id))
		},
		Args: cobra.MinimumNArgs(1),
	}
	cacreateuserCmd.Flags().StringP("id", "i", "", "user id")
	var cabootCmd = &cobra.Command{
		Use:   "ca-bootstrap",
		Run: func(cmd *cobra.Command, args []string) {
		  //cm := NewCertManager(0x99)
		  fabric := newFabric()
		  fabric.certificateManager.BootstrapCa()
		},
	}
	var discoverCmd = &cobra.Command{
		Use:   "discover",
		Run: func(cmd *cobra.Command, args []string) {
			device, _ := cmd.Flags().GetString("device")
			qrtext, _ := cmd.Flags().GetString("qr")
			devices, err := discover(device)
			if err != nil {
				panic(err)
			}
			if len(qrtext) > 0 {
				qr := decode_qr_text(qrtext)
				device := filter_devices(devices, qr)
				devices = []Device{device}
			}
			for _, device := range devices {
				device.Dump()
				fmt.Println("")
			}
		},
	}
	var decodeQrCmd = &cobra.Command{
		Use:   "decode-qr",
		Short: "decode text representation of qr code",
		Run: func(cmd *cobra.Command, args []string) {
			qrtext := args[0]
			qr := decode_qr_text(qrtext)
			qr.dump()
		},
		Args: cobra.MinimumNArgs(1),
	}
	var decodeManualCmd = &cobra.Command{
		Use:   "decode-mc",
		Short: "decode manual pairing code",
		Run: func(cmd *cobra.Command, args []string) {
			text := args[0]
			content := decode_manual_code(text)
			fmt.Printf("passcode: %d\n", content.passcode)
			fmt.Printf("discriminator4: %d\n", content.discriminator4)
		},
		Args: cobra.MinimumNArgs(1),
	}
	discoverCmd.Flags().StringP("device", "d", "", "network device")
	discoverCmd.Flags().StringP("qr", "q", "", "qr code")
	rootCmd.AddCommand(cacreateuserCmd)
	rootCmd.AddCommand(cabootCmd)
	rootCmd.AddCommand(commissionCmd)
	rootCmd.AddCommand(offCmd)
	rootCmd.AddCommand(onCmd)
	rootCmd.AddCommand(readCmd)
	rootCmd.AddCommand(discoverCmd)
	rootCmd.AddCommand(decodeQrCmd)
	rootCmd.AddCommand(decodeManualCmd)
	rootCmd.AddCommand(list_fabricsCmd)
	rootCmd.Execute()
}
