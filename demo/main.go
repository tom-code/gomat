package main

import (
	"fmt"
	"log"
	randm "math/rand"
	"net"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/tom-code/gomat/onboarding_payload"
	"github.com/tom-code/gomat"
)


func filter_devices(devices []gomat.DiscoveredDevice, qr onboarding_payload.QrContent) gomat.DiscoveredDevice {
	for _, device := range(devices) {
		log.Printf("%s %d\n", device.D, qr.Discriminator)
		if device.D != fmt.Sprintf("%d", qr.Discriminator) {
			continue
		}
		if device.VendorId != int(qr.Vendor) {
			continue
		}
		if device.ProductId != int(qr.Product) {
			continue
		}
		return device
	}
	panic("not foind")
}

func discover_with_qr(qr string) gomat.DiscoveredDevice {
	var devices []gomat.DiscoveredDevice
	var err error
	for i:=0; i<5; i++ {
		devices, err = gomat.Discover("en0")
		if err != nil {
			panic(err)
		}
		if len(devices) > 0 {
			break
		}

	}
	device := filter_devices(devices, onboarding_payload.DecodeQrText(qr))
	return device
}


/*
func command_list_fabrics(fabric *gomat.Fabric, ip net.IP, controller_id, device_id uint64) {

	channel := gomat.NewChannel(ip, 5540, 55555)
	secure_channel := gomat.SecureChannel {
		Udp: &channel,
		Counter: uint32(randm.Intn(0xffffffff)),
	}
	secure_channel = gomat.SigmaExchange(fabric, controller_id, device_id, secure_channel)

	to_send := gomat.InvokeRead(0, 0x3e, 1)
	secure_channel.Send(to_send)

	resp := secure_channel.Receive()
	resp.Tlv.Dump(0)
}*/


func createBasicFabric(id uint64) *gomat.Fabric {
	cert_manager := gomat.NewFileCertManager(id)
	cert_manager.Load()
	fabric := gomat.NewFabric(id, cert_manager)
	return fabric
}

func createBasicFabricFromCmd(cmd *cobra.Command) *gomat.Fabric {
	fabric_id_str, _ := cmd.Flags().GetString("fabric")
	id, err := strconv.ParseUint(fabric_id_str, 0, 64)
	if err != nil {
		panic(fmt.Sprintf("invalid fabric id %s", fabric_id_str))
	}
	return createBasicFabric(id)
}

func connectDeviceFromCmd(fabric *gomat.Fabric, cmd *cobra.Command) (gomat.SecureChannel, error) {
	ip, _ := cmd.Flags().GetString("ip")
	device_id,_ := cmd.Flags().GetUint64("device-id")
	controller_id,_ := cmd.Flags().GetUint64("controller-id")

	channel := gomat.NewChannel(net.ParseIP(ip), 5540, 55555)
	secure_channel := gomat.SecureChannel {
		Udp: &channel,
		Counter: uint32(randm.Intn(0xffffffff)),
	}
	var err error
	secure_channel, err = gomat.SigmaExchange(fabric, controller_id, device_id, secure_channel)
	return secure_channel, err
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "gomat",
		Short: "matter manager",
	}
	rootCmd.PersistentFlags().StringP("fabric", "f", "0x110", "fabric identifier")

	var commandCmd = &cobra.Command{
		Use: "cmd",
	}
	commandCmd.PersistentFlags().Uint64P("device-id", "", 2, "device id")
	commandCmd.PersistentFlags().Uint64P("controller-id", "", 9, "controller id")
	commandCmd.PersistentFlags().StringP("ip", "i", "", "ip address")

	commandCmd.AddCommand( &cobra.Command{
		Use: "off",
		Run: func(cmd *cobra.Command, args []string) {
			fabric := createBasicFabricFromCmd(cmd)
			channel, err := connectDeviceFromCmd(fabric, cmd)
			if err != nil {
				panic(err)
			}
			to_send := gomat.InvokeCommand(1, 6, 0, []byte{})
			channel.Send(to_send)

			resp, err := channel.Receive()
			if err != nil {
				panic(err)
			}
			status, err := resp.Tlv.GetIntRec([]int{1,0,1,1,0})
			if err != nil {
				panic(err)
			}
			fmt.Printf("result status: %d\n", status)
		},
	})

	commandCmd.AddCommand( &cobra.Command{
		Use: "on",
		Run: func(cmd *cobra.Command, args []string) {
			fabric := createBasicFabricFromCmd(cmd)
			channel, err := connectDeviceFromCmd(fabric, cmd)
			if err != nil {
				panic(err)
			}
			to_send := gomat.InvokeCommand(1, 6, 1, []byte{})
			channel.Send(to_send)

			resp, err := channel.Receive()
			if err != nil {
				panic(err)
			}
			status, err := resp.Tlv.GetIntRec([]int{1,0,1,1,0})
			if err != nil {
				panic(err)
			}
			fmt.Printf("result status: %d\n", status)
		},
	})

	commandCmd.AddCommand( &cobra.Command{
		Use: "read",
		Run: func(cmd *cobra.Command, args []string) {
			fabric := createBasicFabricFromCmd(cmd)
			channel, err := connectDeviceFromCmd(fabric, cmd)
			if err != nil {
				panic(err)
			}

			endpoint, _ := strconv.ParseInt(args[0], 0, 16)
			cluster, _ := strconv.ParseInt(args[1], 0, 16)
			attr, _ := strconv.ParseInt(args[2], 0, 16)

			to_send := gomat.InvokeRead(byte(endpoint), byte(cluster), byte(attr))
			channel.Send(to_send)

			resp, err := channel.Receive()
			if err != nil {
				panic(err)
			}
			resp.Tlv.Dump(0)

		},
		Args: cobra.MinimumNArgs(3),
	})


	rootCmd.AddCommand(commandCmd)

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
			fabric := createBasicFabricFromCmd(cmd)
			device_id,_ := cmd.Flags().GetUint64("device-id")
			controller_id,_ := cmd.Flags().GetUint64("controller-id")
			pinn, err := strconv.Atoi(pin)
			if err != nil {
				panic(err)
			}
			//commision(fabric, discover_with_qr(qr).addrs[1], 123456)
			err = gomat.Commision(fabric, net.ParseIP(ip), pinn, controller_id, device_id)
			if err != nil {
				panic(err)
			}
		},
	}
	commissionCmd.Flags().StringP("ip", "i", "", "ip address")
	commissionCmd.Flags().StringP("pin", "p", "", "pin")
	commissionCmd.Flags().Uint64P("device-id", "", 2, "device id")
	commissionCmd.Flags().Uint64P("controller-id", "", 9, "controller id")


	var cacreateuserCmd = &cobra.Command{
		Use:   "ca-createuser [id]",
		Run: func(cmd *cobra.Command, args []string) {
		  ids := args[0]
		  id, err := strconv.ParseUint(ids, 0, 64)
		  if err != nil {
			panic(err)
		  }
		  //cm := NewCertManager(0x99)
		  fabric := createBasicFabricFromCmd(cmd)
		  fabric.CertificateManager.Load()
		  err = fabric.CertificateManager.CreateUser(uint64(id))
		  if err != nil {
			panic(err)
		  }

		},
		Args: cobra.MinimumNArgs(1),
	}
	cacreateuserCmd.Flags().StringP("id", "i", "", "user id")
	var cabootCmd = &cobra.Command{
		Use:   "ca-bootstrap",
		Run: func(cmd *cobra.Command, args []string) {
		  //cm := NewCertManager(0x99)
		  fabric := createBasicFabricFromCmd(cmd)
		  fabric.CertificateManager.BootstrapCa()
		},
	}
	var discoverCmd = &cobra.Command{
		Use:   "discover",
		Run: func(cmd *cobra.Command, args []string) {
			device, _ := cmd.Flags().GetString("device")
			qrtext, _ := cmd.Flags().GetString("qr")
			devices, err := gomat.Discover(device)
			if err != nil {
				panic(err)
			}
			if len(qrtext) > 0 {
				qr := onboarding_payload.DecodeQrText(qrtext)
				device := filter_devices(devices, qr)
				devices = []gomat.DiscoveredDevice{device}
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
			qr := onboarding_payload.DecodeQrText(qrtext)
			qr.Dump()
		},
		Args: cobra.MinimumNArgs(1),
	}
	var decodeManualCmd = &cobra.Command{
		Use:   "decode-mc",
		Short: "decode manual pairing code",
		Run: func(cmd *cobra.Command, args []string) {
			text := args[0]
			content := onboarding_payload.DecodeManualPairingCode(text)
			fmt.Printf("passcode: %d\n", content.Passcode)
			fmt.Printf("discriminator4: %d\n", content.Discriminator4)
		},
		Args: cobra.MinimumNArgs(1),
	}
	discoverCmd.Flags().StringP("device", "d", "", "network device")
	discoverCmd.Flags().StringP("qr", "q", "", "qr code")
	rootCmd.AddCommand(cacreateuserCmd)
	rootCmd.AddCommand(cabootCmd)
	rootCmd.AddCommand(commissionCmd)
	rootCmd.AddCommand(discoverCmd)
	rootCmd.AddCommand(decodeQrCmd)
	rootCmd.AddCommand(decodeManualCmd)
	rootCmd.Execute()
}
