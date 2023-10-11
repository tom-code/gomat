package main

import (
	"bytes"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"gomat/ca"
	"gomat/tlvdec"
	"io"
	"log"
	"net"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/hkdf"
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


	controller_privkey, _ := ecdh.P256().GenerateKey(rand.Reader)
	sigma1_payload := genSigma1(controller_privkey)
	sigma1 := genSigma1Req(sigma1_payload)
	channel.send(sigma1)
	sigma2, _ := channel.receive()
	sigma2dec := decodegen(sigma2)
	sigma2dec.tlv.Dump(0)

	ack = AckS(uint32(channel.get_counter()), sigma2dec.msg.messageCounter)
	channel.send(ack)

	controller_key := ca.Generate_and_store_key_ecdsa("controller")
	controller_csr := x509.CertificateRequest {
		PublicKey: &controller_key.PublicKey,
	}
	controller_cert := sign_cert(&controller_csr, 9, "controller")
	conrtoller_cert_matter := MatterCert2(controller_cert)

	var tlv_s3tbs TLVBuffer
	tlv_s3tbs.writeAnonStruct()
	tlv_s3tbs.writeOctetString(1, conrtoller_cert_matter)
	tlv_s3tbs.writeOctetString(3, controller_privkey.PublicKey().Bytes())
	responder_public := sigma2dec.tlv.GetOctetStringRec([]int{3})
	tlv_s3tbs.writeOctetString(4, responder_public)
	tlv_s3tbs.writeAnonStructEnd()
	log.Printf("responder public %s\n", hex.EncodeToString(responder_public))
	s2 := sha256.New()
	s2.Write(tlv_s3tbs.data.Bytes())
	tlv_s3tbs_hash := s2.Sum(nil)
	sr, ss, err := ecdsa.Sign(rand.Reader, controller_key, tlv_s3tbs_hash)
	if err != nil {
		panic(err)
	}
	tlv_s3tbs_out :=  append(sr.Bytes(), ss.Bytes()...)

	var tlv_s3tbe TLVBuffer
	tlv_s3tbe.writeAnonStruct()
	tlv_s3tbe.writeOctetString(1, conrtoller_cert_matter)
	tlv_s3tbe.writeOctetString(3, tlv_s3tbs_out)
	tlv_s3tbe.writeAnonStructEnd()

	pub, err := ecdh.P256().NewPublicKey(responder_public)
	if err != nil {
		panic(err)
	}
	shared_secret, err := controller_privkey.ECDH(pub)
	if err != nil {
		panic(err)
	}
	log.Println(shared_secret)
	s3k_th := sigma1_payload
	s3k_th = append(s3k_th, sigma2dec.payload...)
	log.Printf("transcript %s\n", hex.EncodeToString(s3k_th))
	log.Printf("transcript_a %s\n", hex.EncodeToString(genSigma1(controller_privkey)))
	log.Printf("transcript_b %s\n", hex.EncodeToString(sigma2dec.payload))
	s2 = sha256.New()
	s2.Write(s3k_th)
	transcript_hash := s2.Sum(nil)
	log.Printf("transcript hash %s\n", hex.EncodeToString(transcript_hash))
	s3_salt := make_ipk()
	s3_salt = append(s3_salt, transcript_hash...)
	log.Printf("s3 salt %s\n", hex.EncodeToString(s3_salt))
	log.Printf("s3 shared %s\n", hex.EncodeToString(shared_secret))
	s3kengine := hkdf.New(sha256.New, shared_secret, s3_salt, []byte("Sigma3"))
	s3k := make([]byte, 16)
	if _, err := io.ReadFull(s3kengine, s3k); err != nil {
		panic(err)
	}


	log.Printf("key %s\n", hex.EncodeToString(s3k))
	c, err := aes.NewCipher(s3k)
	if err != nil {
		panic(err)
	}
	ccm, err := NewCCMWithNonceAndTagSizes(c, len(nonce), 16)
	if err != nil {
		panic(err)
	}
	CipherText := ccm.Seal(nil, []byte("NCASE_Sigma3N"), tlv_s3tbe.data.Bytes(), []byte{})
	log.Printf("ciphertext %s", hex.EncodeToString(CipherText))


	var tlv_s3 TLVBuffer
	tlv_s3.writeAnonStruct()
	tlv_s3.writeOctetString(1, CipherText)
	tlv_s3.writeAnonStructEnd()

	to_send = genSigma3Req(tlv_s3.data.Bytes())

	channel.send(to_send)

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
