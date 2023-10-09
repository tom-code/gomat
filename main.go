package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"gomat/ca"
	"gomat/tlvdec"
	"log"
	"net"

	"github.com/spf13/cobra"
)

func make_nonce(counter uint32) []byte{
	var n bytes.Buffer
	n.WriteByte(0)
	binary.Write(&n, binary.LittleEndian, counter)
	n.Write([]byte{0,0,0,0,0,0,0,0})
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
func (ch *Channel)get_counter() int {
	ch.out_counter = ch.out_counter + 1
	return int(ch.out_counter)
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

func hex2bin(in string) []byte {
	out, _ := hex.DecodeString(in)
	return out
}

func make_sha1(in []byte) []byte {
	h := sha1.New()
	return h.Sum(in)
}

func flow() {
	//tlvdec.Test1()
	//panic("")
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
	device := devices[0]

	channel := NewChannel(device.addrs[1], 5540, 55555)

	pbkdf_request := PBKDFParamRequest()
	channel.send(pbkdf_request)

	pbkdf_response, _ := channel.receive()
	pbkdf_response_decoded := decode(pbkdf_response)
	log.Println(pbkdf_response_decoded)

	ack := Ack(uint32(channel.get_counter()), pbkdf_response_decoded.messageCounter)
	channel.send(ack)

	sctx := newSpaceCtx()
	sctx.gen_w(123456, pbkdf_response_decoded.PBKDFParamResponse.salt, pbkdf_response_decoded.PBKDFParamResponse.iterations)
	sctx.gen_random_X()
	sctx.calc_X()

	pake1 := Pake1ParamRequest(sctx.X.as_bytes(), uint32(channel.get_counter()))
	channel.send(pake1)

	pake2, _ := channel.receive()
	log.Printf("pake2 %s\n", hex.EncodeToString(pake2))
	pake2_decoded := decode(pake2)
	log.Println(pake2_decoded)

	ack = Ack(uint32(channel.get_counter()), pake2_decoded.messageCounter)
	channel.send(ack)

	sctx.Y.from_bytes(pake2_decoded.PAKE2ParamResponse.pb)
	sctx.calc_ZV()
	ttseed := []byte("CHIP PAKE V1 Commissioning")
	ttseed = append(ttseed, pbkdf_request[22:]...)
	ttseed = append(ttseed, pbkdf_response[26:]...)
	sctx.calc_hash(ttseed)

	pake3 := Pake3ParamRequest(sctx.cA, uint32(channel.get_counter()))
	channel.send(pake3)

	status_report, _ := channel.receive()
	status_report_decoded := decode(status_report)
	status_report_decoded.StatusReport.dump()
	ack = Ack(uint32(channel.get_counter()), status_report_decoded.messageCounter)
	channel.send(ack)
	log.Printf("remote node id: %s", hex.EncodeToString(status_report_decoded.sourceNodeId))



	b := "c4f68604b151d21f2afac9e61a745ade93fde7dce1c6615de543f230bd62dd85"
	bb, _ := hex.DecodeString(b)
	var tlv TLVBuffer
	tlv.writeOctetString(0, bb)
	to_send := invokeCommand2(0, 0x3e, 4, tlv.data.Bytes())




	log.Printf("responder session %x\n", pbkdf_response_decoded.PBKDFParamResponse.responderSession)
	var cnt uint32
	cnt = uint32(channel.get_counter())
	nonce := make_nonce(cnt)
	sec := Secured(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, to_send, sctx.encrypt_key, nonce)
	channel.send(sec)

	channel.receive() // ack
	csr_response, _ := channel.receive()
	ds := decodeSecured(csr_response, sctx.decrypt_key)


	ack = Ack3(ds.msg.messageCounter)
	cnt = uint32(channel.get_counter())
	nonce = make_nonce(cnt)
	sec = Secured(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, ack, sctx.encrypt_key, nonce)
	channel.send(sec)


	nocsr := ds.tlv.GetOctetStringRec([]int{1,0,0,1,0})
	tlv2 := tlvdec.Decode(nocsr)
	tlv2.Dump(0)
	csr := tlv2.GetOctetStringRec([]int{1})
	csrp, err := x509.ParseCertificateRequest(csr)
	log.Printf("csr %+v\n", csrp)
	log.Println(csrp.PublicKey)


	//AddTrustedRootCertificate
	var tlv4 TLVBuffer
	tlv4.writeOctetString(0, CAMatterCert2())
	to_send = invokeCommand2(0, 0x3e, 0xb, tlv4.data.Bytes())

	cnt = uint32(channel.get_counter())
	nonce = make_nonce(cnt)
	sec = Secured(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, to_send, sctx.encrypt_key, nonce)
	channel.send(sec)

	channel.receive() // ack
	add_root_cer_response, _ := channel.receive()
	ds = decodeSecured(add_root_cer_response, sctx.decrypt_key)
	ds.tlv.Dump(0)

	ack = Ack3(ds.msg.messageCounter)
	cnt = uint32(channel.get_counter())
	nonce = make_nonce(cnt)
	sec = Secured(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, ack, sctx.encrypt_key, nonce)
	channel.send(sec)

	noc_x509 := sign_cert(csrp, 2, "user")
	noc_matter := MatterCert2(noc_x509)
	//AddNOC
	var tlv5 TLVBuffer
	tlv5.writeOctetString(0, noc_matter)
	tlv5.writeOctetString(2, []byte{0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf}) //ipk
	tlv5.writeUInt(3, TYPE_UINT_2, 100)
	tlv5.writeUInt(4, TYPE_UINT_2, 101)
	to_send = invokeCommand2(0, 0x3e, 0x6, tlv5.data.Bytes())

	cnt = uint32(channel.get_counter())
	nonce = make_nonce(cnt)
	sec = Secured(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, to_send, sctx.encrypt_key, nonce)
	channel.send(sec)

	channel.receive() // ack
	addnoc_response, _ := channel.receive()
	ds = decodeSecured(addnoc_response, sctx.decrypt_key)
	ds.tlv.Dump(0)

	ack = Ack3(ds.msg.messageCounter)
	cnt = uint32(channel.get_counter())
	nonce = make_nonce(cnt)
	sec = Secured(uint16(pbkdf_response_decoded.PBKDFParamResponse.responderSession), cnt, ack, sctx.encrypt_key, nonce)
	channel.send(sec)


	sigma1 := genSigma1Req()
	channel.send(sigma1)
	sigma2, _ := channel.receive()
	sigma2dec := decodegen(sigma2)
	sigma2dec.tlv.Dump(0)
}


func main() {
	var rootCmd = &cobra.Command{
		Use:   "mama",
		Short: "matter manager",
	}
	var flowCmd = &cobra.Command{
		Use:   "flow",
		Run: func(cmd *cobra.Command, args []string) {
		  flow()
		},
	}
	var cakeygenCmd = &cobra.Command{
		Use:   "ca-keygen",
		Run: func(cmd *cobra.Command, args []string) {
		  ca.Create_ca_cert()
		},
	}
	var testCmd = &cobra.Command{
		Use:   "test",
		Run: func(cmd *cobra.Command, args []string) {
		  tlvdec.Test2()
		},
	}
	rootCmd.AddCommand(flowCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(cakeygenCmd)
	rootCmd.Execute()
}
