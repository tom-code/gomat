package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tom-code/gomat"
	"github.com/tom-code/gomat/discover"
	"github.com/tom-code/gomat/mattertlv"
	"github.com/tom-code/gomat/onboarding_payload"
	"github.com/tom-code/gomat/symbols"
)

func filter_devices(devices []discover.DiscoveredDevice, qr onboarding_payload.QrContent) []discover.DiscoveredDevice {
	out := []discover.DiscoveredDevice{}
	for _, device := range devices {
		if device.D != fmt.Sprintf("%d", qr.Discriminator) {
			continue
		}
		if device.VendorId != int(qr.Vendor) {
			continue
		}
		if device.ProductId != int(qr.Product) {
			continue
		}
		out = append(out, device)
	}
	return out
}

func command_list_fabrics(cmd *cobra.Command) {

	fabric := createBasicFabricFromCmd(cmd)
	channel, err := connectDeviceFromCmd(fabric, cmd)
	if err != nil {
		panic(err)
	}

	to_send := gomat.EncodeIMReadRequest(0, 0x3e, 1)
	channel.Send(to_send)

	resp, err := channel.Receive()
	if err != nil {
		panic(err)
	}
	if resp.ProtocolHeader.Opcode != gomat.INTERACTION_OPCODE_REPORT_DATA {
		panic("did not receive report data message")
	}

	fabric_array := resp.Tlv.GetItemRec([]int{1, 0, 1, 2})
	if fabric_array == nil {
		panic("did not receive fabric list")
	}
	for _, fabr := range fabric_array.GetChild() {
		root_key := fabr.GetItemWithTag(1)
		if root_key != nil {
			fmt.Printf("root_key: %s\n", hex.EncodeToString(root_key.GetOctetString()))
		}
		vendor_id := fabr.GetItemWithTag(2)
		if vendor_id != nil {
			fmt.Printf("vendor_id: %d\n", vendor_id.GetInt())
		}
		fabric_id := fabr.GetItemWithTag(3)
		if fabric_id != nil {
			fmt.Printf("fabric_id: %d\n", fabric_id.GetInt())
		}
		node_id := fabr.GetItemWithTag(4)
		if node_id != nil {
			fmt.Printf("node_id: %d\n", node_id.GetInt())
		}
		fmt.Println("---------------------------------")
	}
	dict := map[string]string{
		".0":             "Root",
		".0.1":           "AttributeReports",
		".0.1.0":         "AttributeReportIB",
		".0.1.0.1":       "AttributeData",
		".0.1.0.1.0":     "Version",
		".0.1.0.1.1":     "Path",
		".0.1.0.1.1.2":   "Endpoint",
		".0.1.0.1.1.3":   "Cluster",
		".0.1.0.1.1.4":   "Attribute",
		".0.1.0.1.2":     "Data",
		".0.1.0.1.2.0":   "Fabrics",
		".0.1.0.1.2.0.1": "RootPublicKey",
		".0.1.0.1.2.0.2": "VendorId",
		".0.1.0.1.2.0.3": "FabricId",
		".0.1.0.1.2.0.4": "NodeId",
		".0.1.0.1.2.0.5": "Label",
	}
	resp.Tlv.DumpWithDict(0, "", dict)
}

func command_list_device_types(cmd *cobra.Command) {

	fabric := createBasicFabricFromCmd(cmd)
	channel, err := connectDeviceFromCmd(fabric, cmd)
	if err != nil {
		panic(err)
	}

	to_send := gomat.EncodeIMReadRequest(0, symbols.CLUSTER_ID_Descriptor, symbols.ATTRIBUTE_ID_Descriptor_DeviceTypeList)
	channel.Send(to_send)

	resp, err := channel.Receive()
	if err != nil {
		panic(err)
	}
	if resp.ProtocolHeader.Opcode != gomat.INTERACTION_OPCODE_REPORT_DATA {
		panic("did not receive report data message")
	}

	dict := map[string]string{
		".0":             "Root",
		".0.1":           "AttributeReports",
		".0.1.0":         "AttributeReportIB",
		".0.1.0.1":       "AttributeData",
		".0.1.0.1.0":     "Version",
		".0.1.0.1.1":     "Path",
		".0.1.0.1.1.2":   "Endpoint",
		".0.1.0.1.1.3":   "Cluster",
		".0.1.0.1.1.4":   "Attribute",
		".0.1.0.1.2":     "Data",
		".0.1.0.1.2.0":   "DeviceType",
		".0.1.0.1.2.0.0": "DeviceType",
		".0.1.0.1.2.0.1": "Revision",
	}
	resp.Tlv.DumpWithDict(0, "", dict)
}

func command_list_supported_clusters(cmd *cobra.Command, args []string) {

	fabric := createBasicFabricFromCmd(cmd)
	channel, err := connectDeviceFromCmd(fabric, cmd)
	if err != nil {
		panic(err)
	}
	endpoint, err := strconv.ParseInt(args[0], 0, 16)
	if err != nil {
		panic(err)
	}

	to_send := gomat.EncodeIMReadRequest(uint16(endpoint), symbols.CLUSTER_ID_Descriptor, symbols.ATTRIBUTE_ID_Descriptor_ServerList)
	channel.Send(to_send)

	resp, err := channel.Receive()
	if err != nil {
		panic(err)
	}
	if resp.ProtocolHeader.Opcode != gomat.INTERACTION_OPCODE_REPORT_DATA {
		panic("did not receive report data message")
	}

	dict := map[string]string{
		".0":           "Root",
		".0.1":         "AttributeReports",
		".0.1.0":       "AttributeReportIB",
		".0.1.0.1":     "AttributeData",
		".0.1.0.1.0":   "Version",
		".0.1.0.1.1":   "Path",
		".0.1.0.1.1.2": "Endpoint",
		".0.1.0.1.1.3": "Cluster",
		".0.1.0.1.1.4": "Attribute",
		".0.1.0.1.2":   "Data",
		".0.1.0.1.2.0": "ClusterId",
	}
	resp.Tlv.DumpWithDict(0, "", dict)
	clusters := resp.Tlv.GetItemRec([]int{1, 0, 1, 2})
	if clusters == nil {
		panic("clusters not found")
	}
	for _, c := range clusters.GetChild() {
		name := symbols.ClusterNameMap[c.GetInt()]
		fmt.Printf("0x%x %s\n", c.GetInt(), name)
	}
}

func command_list_interfaces(cmd *cobra.Command, args []string) {

	fabric := createBasicFabricFromCmd(cmd)
	channel, err := connectDeviceFromCmd(fabric, cmd)
	if err != nil {
		panic(err)
	}

	to_send := gomat.EncodeIMReadRequest(0, symbols.CLUSTER_ID_GeneralDiagnostics, symbols.ATTRIBUTE_ID_GeneralDiagnostics_NetworkInterfaces)
	channel.Send(to_send)

	resp, err := channel.Receive()
	if err != nil {
		panic(err)
	}
	if resp.ProtocolHeader.Opcode != gomat.INTERACTION_OPCODE_REPORT_DATA {
		panic("did not receive report data message")
	}
	dict := map[string]string{
		".0":             "Root",
		".0.1":           "AttributeReports",
		".0.1.0":         "AttributeReportIB",
		".0.1.0.1":       "AttributeData",
		".0.1.0.1.0":     "Version",
		".0.1.0.1.1":     "Path",
		".0.1.0.1.1.2":   "Endpoint",
		".0.1.0.1.1.3":   "Cluster",
		".0.1.0.1.1.4":   "Attribute",
		".0.1.0.1.2":     "Data",
		".0.1.0.1.2.0":   "Interface",
		".0.1.0.1.2.0.0": "Name",
		".0.1.0.1.2.0.1": "IsOperational",
		".0.1.0.1.2.0.4": "HWAddress",
		".0.1.0.1.2.0.5": "ipv4Address",
		".0.1.0.1.2.0.6": "ipv6Address",
		".0.1.0.1.2.0.7": "type",
	}
	resp.Tlv.DumpWithDict(0, "", dict)
}

func command_get_logs(cmd *cobra.Command, args []string) {

	fabric := createBasicFabricFromCmd(cmd)
	channel, err := connectDeviceFromCmd(fabric, cmd)
	if err != nil {
		panic(err)
	}
	endpoint, err := strconv.ParseInt(args[0], 0, 16)
	if err != nil {
		panic(err)
	}

	var tlv mattertlv.TLVBuffer
	tlv.WriteUInt8(0, 0) // intent
	tlv.WriteUInt8(1, 0)

	to_send := gomat.EncodeIMInvokeRequest(uint16(endpoint), symbols.CLUSTER_ID_DiagnosticLogs, symbols.COMMAND_ID_DiagnosticLogs_RetrieveLogsRequest, tlv.Bytes(), false, uint16(rand.Intn(0xffff)))
	channel.Send(to_send)

	resp, err := channel.Receive()
	if err != nil {
		panic(err)
	}
	if resp.ProtocolHeader.Opcode != gomat.INTERACTION_OPCODE_INVOKE_RSP {
		panic("did not receive report data message")
	}

	resp.Tlv.Dump(1)
}

func command_open_commissioning(cmd *cobra.Command, args []string) {
	pin, err := strconv.ParseInt(args[0], 0, 16)
	if err != nil {
		panic(err)
	}

	fabric := createBasicFabricFromCmd(cmd)
	channel, err := connectDeviceFromCmd(fabric, cmd)
	if err != nil {
		panic(err)
	}
	salt := gomat.CreateRandomBytes(32)
	iterations := 1000
	sctx := gomat.NewSpaceCtx()
	sctx.Gen_w(int(pin), salt, iterations)
	sctx.Gen_random_X()
	sctx.Gen_random_Y()
	sctx.Calc_X()
	sctx.Calc_ZVb()
	data := sctx.W0
	data = append(data, sctx.L.As_bytes()...)

	var tlv mattertlv.TLVBuffer
	tlv.WriteUInt8(0, 240)                 // timeout
	tlv.WriteOctetString(1, data)          // pake
	tlv.WriteUInt16(2, 1000)               // discrimantor
	tlv.WriteUInt32(3, uint32(iterations)) // iterations
	tlv.WriteOctetString(4, salt)          // salt

	var exchange uint16 = uint16(rand.Intn(0xffff))
	to_send := gomat.EncodeIMTimedRequest(exchange, 6000)
	channel.Send(to_send)
	resp, err := channel.Receive()
	if err != nil {
		panic(err)
	}
	if resp.ProtocolHeader.Opcode == gomat.INTERACTION_OPCODE_STATUS_RSP {
		status := resp.Tlv.GetItemWithTag(0)
		if status != nil {
			if status.GetInt() != 0 {
				panic(fmt.Sprintf("TimedRequest failed with status: %d\n", status.GetInt()))
			}
		} else {
			log.Printf("TimedRequest status parse failed %v\n", resp.Payload)
		}
	} else {
		resp.ProtocolHeader.Dump()
		panic("unexpected opcode")
	}

	to_send = gomat.EncodeIMInvokeRequest(0, symbols.CLUSTER_ID_AdministratorCommissioning, symbols.COMMAND_ID_AdministratorCommissioning_OpenCommissioningWindow, tlv.Bytes(), true, exchange)
	channel.Send(to_send)

	resp, err = channel.Receive()
	if err != nil {
		panic(err)
	}

	if resp.ProtocolHeader.Opcode != gomat.INTERACTION_OPCODE_INVOKE_RSP {
		panic("did not receive report data message")
	}

	final_result := gomat.ParseImInvokeResponse(&resp.Tlv)
	switch final_result {
	case 0:
		log.Println("open commissioning success")
	case 2:
		log.Println("failed with busy (2)")
	case 3:
		log.Println("failed with pake parameter error (3)")
	case 4:
		log.Println("failed with window not open (4)")
	default:
		log.Printf("failed with unknown code 0x%x\n", final_result)
	}
}

func test_subscribe(cmd *cobra.Command, args []string) {
	fabric := createBasicFabricFromCmd(cmd)
	channel, err := connectDeviceFromCmd(fabric, cmd)
	if err != nil {
		panic(err)
	}

	endpoint, _ := strconv.ParseInt(args[0], 0, 16)
	cluster, _ := strconv.ParseInt(args[1], 0, 16)
	event, _ := strconv.ParseInt(args[2], 0, 16)
	to_send := gomat.EncodeIMSubscribeRequest(uint16(endpoint), uint32(cluster), uint32(event))
	channel.Send(to_send)

	resp, err := channel.Receive()
	if err != nil {
		panic(err)
	}
	if resp.ProtocolHeader.Opcode != gomat.INTERACTION_OPCODE_REPORT_DATA {
		log.Println("unexpected message")
		resp.ProtocolHeader.Dump()
	} else {
		resp.Tlv.DumpWithDict(0, "", report_data_dictionary)
	}

	sr := gomat.EncodeIMStatusResponse(resp.ProtocolHeader.ExchangeId, 1)
	channel.Send(sr)
	for {
		r, err := channel.Receive()
		if err != nil {
			log.Println("it is ok to see timeout on following line")
			log.Println(err)
			continue
		}
		if r.ProtocolHeader.Opcode == gomat.INTERACTION_OPCODE_SUBSC_RSP {
			log.Println("subscribe response")
			continue
		}
		if r.ProtocolHeader.Opcode == gomat.INTERACTION_OPCODE_STATUS_RSP {
			log.Println("status response")
			continue
		}
		if r.ProtocolHeader.Opcode == gomat.INTERACTION_OPCODE_REPORT_DATA {
			fmt.Printf("EVENT:\n")
			r.Tlv.DumpWithDict(0, "", report_data_dictionary)
			sr = gomat.EncodeIMStatusResponse(r.ProtocolHeader.ExchangeId, 0)
			channel.Send(sr)
		} else {
			log.Printf("unexpected opcode %x\n", r.ProtocolHeader.Opcode)
			r.ProtocolHeader.Dump()
		}
	}
}

func createBasicFabric(id uint64) *gomat.Fabric {
	cert_manager := gomat.NewFileCertManager(id)
	err := cert_manager.Load()
	if err != nil {
		panic(err)
	}
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
	device_id, _ := cmd.Flags().GetUint64("device-id")
	controller_id, _ := cmd.Flags().GetUint64("controller-id")

	secure_channel, err := gomat.StartSecureChannel(net.ParseIP(ip), 5540, 55555)
	if err != nil {
		panic(err)
	}
	secure_channel, err = gomat.SigmaExchange(fabric, controller_id, device_id, secure_channel)
	return secure_channel, err
}

var report_data_dictionary = map[string]string{
	".0":           "Root",
	".0.0":         "SubscriptionID",
	".0.1":         "AttributeReports",
	".0.2":         "EventReports",
	".0.2.0":       "EventReport",
	".0.2.0.0":     "EventStatus",
	".0.2.0.1":     "EventData",
	".0.2.0.1.0":   "Path",
	".0.2.0.1.0.0": "Node",
	".0.2.0.1.0.1": "Endpoint",
	".0.2.0.1.0.2": "Cluster",
	".0.2.0.1.0.3": "Event",
	".0.2.0.1.0.4": "Urgent",
	".0.2.0.1.1":   "EventNumber",
	".0.2.0.1.2":   "Priority",
	".0.2.0.1.3":   "EpochTimestamp",
	".0.2.0.1.4":   "SystemTimestamp",
	".0.2.0.1.5":   "DeltaEpochTimestamp",
	".0.2.0.1.6":   "DeltaTimestamp",
	".0.2.0.1.7":   "Data",
	".0.3":         "MoreChunkedMessages",
	".0.4":         "SuppressResponse",
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

	commandCmd.AddCommand(&cobra.Command{
		Use: "list_fabrics",
		Run: func(cmd *cobra.Command, args []string) {
			command_list_fabrics(cmd)
		},
	})
	commandCmd.AddCommand(&cobra.Command{
		Use: "list_device_types",
		Run: func(cmd *cobra.Command, args []string) {
			command_list_device_types(cmd)
		},
	})
	commandCmd.AddCommand(&cobra.Command{
		Use: "list_supported_clusters [endpoint]",
		Run: func(cmd *cobra.Command, args []string) {
			command_list_supported_clusters(cmd, args)
		},
		Args: cobra.MinimumNArgs(1),
	})
	commandCmd.AddCommand(&cobra.Command{
		Use: "list_interfaces [endpoint]",
		Run: func(cmd *cobra.Command, args []string) {
			command_list_interfaces(cmd, args)
		},
	})
	commandCmd.AddCommand(&cobra.Command{
		Use: "get_logs [endpoint]",
		Run: func(cmd *cobra.Command, args []string) {
			command_get_logs(cmd, args)
		},
		Args: cobra.MinimumNArgs(1),
	})
	commandCmd.AddCommand(&cobra.Command{
		Use: "open_commissioning",
		Run: func(cmd *cobra.Command, args []string) {
			command_open_commissioning(cmd, args)
		},
		Args: cobra.MinimumNArgs(1),
	})
	commandCmd.AddCommand(&cobra.Command{
		Use: "off",
		Run: func(cmd *cobra.Command, args []string) {
			fabric := createBasicFabricFromCmd(cmd)
			channel, err := connectDeviceFromCmd(fabric, cmd)
			if err != nil {
				panic(err)
			}
			to_send := gomat.EncodeIMInvokeRequest(1, symbols.CLUSTER_ID_OnOff, symbols.COMMAND_ID_OnOff_Off, []byte{}, false, uint16(rand.Intn(0xffff)))
			channel.Send(to_send)

			resp, err := channel.Receive()
			if err != nil {
				panic(err)
			}
			status, err := resp.Tlv.GetIntRec([]int{1, 0, 1, 1, 0})
			if err != nil {
				panic(err)
			}
			fmt.Printf("result status: %d\n", status)
		},
	})

	commandCmd.AddCommand(&cobra.Command{
		Use: "on",
		Run: func(cmd *cobra.Command, args []string) {
			fabric := createBasicFabricFromCmd(cmd)
			channel, err := connectDeviceFromCmd(fabric, cmd)
			if err != nil {
				panic(err)
			}
			to_send := gomat.EncodeIMInvokeRequest(1, symbols.CLUSTER_ID_OnOff, symbols.COMMAND_ID_OnOff_On, []byte{}, false, uint16(rand.Intn(0xffff)))
			channel.Send(to_send)

			resp, err := channel.Receive()
			if err != nil {
				panic(err)
			}
			status, err := resp.Tlv.GetIntRec([]int{1, 0, 1, 1, 0})
			if err != nil {
				panic(err)
			}
			fmt.Printf("result status: %d\n", status)
		},
	})

	commandCmd.AddCommand(&cobra.Command{
		Use: "color [hue] [saturation] [time]",
		Run: func(cmd *cobra.Command, args []string) {
			hue, err := strconv.Atoi(args[0])
			if err != nil {
				panic(err)
			}
			saturation, err := strconv.Atoi(args[1])
			if err != nil {
				panic(err)
			}
			time, err := strconv.Atoi(args[2])
			if err != nil {
				panic(err)
			}
			fabric := createBasicFabricFromCmd(cmd)
			channel, err := connectDeviceFromCmd(fabric, cmd)
			if err != nil {
				panic(err)
			}
			var tlv mattertlv.TLVBuffer
			tlv.WriteUInt8(0, byte(hue))        // hue
			tlv.WriteUInt8(1, byte(saturation)) // saturation
			tlv.WriteUInt8(2, byte(time))       // time
			to_send := gomat.EncodeIMInvokeRequest(1, 0x300, 6, tlv.Bytes(), false, uint16(rand.Intn(0xffff)))
			channel.Send(to_send)

			resp, err := channel.Receive()
			if err != nil {
				panic(err)
			}
			status, err := resp.Tlv.GetIntRec([]int{1, 0, 1, 1, 0})
			if err != nil {
				panic(err)
			}
			fmt.Printf("result status: %d\n", status)
		},
		Args: cobra.MinimumNArgs(3),
	})

	// this sends yellight proprietary command to control indidividual leds on yeelight cube
	commandCmd.AddCommand(&cobra.Command{
		Use: "test",
		Run: func(cmd *cobra.Command, args []string) {

			fabric := createBasicFabricFromCmd(cmd)
			channel, err := connectDeviceFromCmd(fabric, cmd)
			if err != nil {
				panic(err)
			}
			var tlv mattertlv.TLVBuffer
			b := bytes.NewBuffer([]byte{})
			for x:=0; x<5; x++ {
				for y:=0; y<5; y++ {
					b.WriteByte(byte(0xff))
					b.WriteByte(byte(x*50+50))
					b.WriteByte(byte(10))
					b.WriteByte(byte(y*40))
				}
			}
			tlv.WriteOctetString(0, b.Bytes())
			to_send := gomat.EncodeIMInvokeRequest(2, 0x1312fc03, 0x13120007, tlv.Bytes(), false, uint16(rand.Intn(0xffff)))
			channel.Send(to_send)

			resp, err := channel.Receive()
			if err != nil {
				panic(err)
			}
			status, err := resp.Tlv.GetIntRec([]int{1, 0, 1, 1, 0})
			if err != nil {
				panic(err)
			}
			fmt.Printf("result status: %d\n", status)
		},
	})

	commandCmd.AddCommand(&cobra.Command{
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

			to_send := gomat.EncodeIMReadRequest(uint16(endpoint), uint32(cluster), uint32(attr))
			channel.Send(to_send)

			resp, err := channel.Receive()
			if err != nil {
				panic(err)
			}
			if (resp.ProtocolHeader.ProtocolId == gomat.ProtocolIdInteraction) &&
				(resp.ProtocolHeader.Opcode == gomat.INTERACTION_OPCODE_REPORT_DATA) {
				resp.Tlv.Dump(0)
			}
			channel.Close()
		},
		Args: cobra.MinimumNArgs(3),
	})

	commandCmd.AddCommand(&cobra.Command{
		Use:     "subscribe [endpoint] [cluster] [event]",
		Example: "subscribe 1 0x101 1",
		Run:     test_subscribe,
		Args:    cobra.MinimumNArgs(3),
	})

	rootCmd.AddCommand(commandCmd)

	var commissionCmd = &cobra.Command{
		Use: "commission",
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
			device_id, _ := cmd.Flags().GetUint64("device-id")
			controller_id, _ := cmd.Flags().GetUint64("controller-id")
			pinn, err := strconv.Atoi(pin)
			if err != nil {
				panic(err)
			}
			//commision(fabric, discover_with_qr(qr).addrs[1], 123456)
			err = gomat.Commission(fabric, net.ParseIP(ip), pinn, controller_id, device_id)
			if err != nil {
				panic(err)
			}

			cf := fabric.CompressedFabric()
			csf := hex.EncodeToString(cf)
			dids := fmt.Sprintf("%s-%016X", csf, device_id)
			dids = strings.ToUpper(dids)
			fmt.Printf("device identifier: %s\n", dids)
		},
	}
	commissionCmd.Flags().StringP("ip", "i", "", "ip address")
	commissionCmd.Flags().StringP("pin", "p", "", "pin")
	commissionCmd.Flags().Uint64P("device-id", "", 2, "device id")
	commissionCmd.Flags().Uint64P("controller-id", "", 9, "controller id")

	var printInfoCmd = &cobra.Command{
		Use: "fabric-info",
		Run: func(cmd *cobra.Command, args []string) {
			fabric := createBasicFabricFromCmd(cmd)
			cf := fabric.CompressedFabric()
			csf := hex.EncodeToString(cf)
			csf = strings.ToUpper(csf)
			fmt.Printf("compressed-fabric: %s", csf)
		},
	}

	var cacreateuserCmd = &cobra.Command{
		Use: "ca-createuser [id]",
		Run: func(cmd *cobra.Command, args []string) {
			ids := args[0]
			id, err := strconv.ParseUint(ids, 0, 64)
			if err != nil {
				panic(err)
			}
			//cm := NewCertManager(0x99)
			fabric := createBasicFabricFromCmd(cmd)
			err = fabric.CertificateManager.CreateUser(uint64(id))
			if err != nil {
				panic(err)
			}

		},
		Args: cobra.MinimumNArgs(1),
	}
	cacreateuserCmd.Flags().StringP("id", "i", "", "user id")
	var cabootCmd = &cobra.Command{
		Use: "ca-bootstrap",
		Run: func(cmd *cobra.Command, args []string) {
			fabric_id_str, _ := cmd.Flags().GetString("fabric")
			id, err := strconv.ParseUint(fabric_id_str, 0, 64)
			if err != nil {
				panic(fmt.Sprintf("invalid fabric id %s", fabric_id_str))
			}
			cm := gomat.NewFileCertManager(id)
			err = cm.BootstrapCa()
			if err != nil {
				panic(err)
			}
		},
	}

	var discoverCmd = &cobra.Command{
		Use: "discover",
	}
	discoverCmd.PersistentFlags().StringP("interface", "i", "", "network interface")
	discoverCmd.PersistentFlags().BoolP("disable-ipv6", "d", false, "disable ipv6")

	var discoverCCmd = &cobra.Command{
		Use: "commissioned [device-id]",
		Run: func(cmd *cobra.Command, args []string) {
			device, _ := cmd.Flags().GetString("interface")
			disable_ipv6, _ := cmd.Flags().GetBool("disable-ipv6")
			device_filter := ""
			if len(args) == 1 {
				fabric := createBasicFabricFromCmd(cmd)
				dids := args[0]
				device_id, err := strconv.ParseInt(dids, 0, 64)
				if err != nil {
					log.Panicf("incorrect device specification %s", dids)
				}
				cf := fabric.CompressedFabric()
				csf := hex.EncodeToString(cf)
				dids = fmt.Sprintf("%s-%016X", csf, device_id)
				device_filter = strings.ToUpper(dids)
				device_filter = device_filter + "._matter._tcp.local."
			}
			devices := discover.DiscoverAllComissioned(device, disable_ipv6)
			for _, device := range devices {
				if (len(device_filter)) > 0 && device.Name != device_filter {
					continue
				}
				device.Dump()
				fmt.Println()
			}
		},
	}
	var discoverC3Cmd = &cobra.Command{
		Use: "commissioned2 [device-id]",
		Run: func(cmd *cobra.Command, args []string) {
			device, _ := cmd.Flags().GetString("interface")
			disable_ipv6, _ := cmd.Flags().GetBool("disable-ipv6")
			device_filter := ""
			if len(args) == 1 {
				fabric := createBasicFabricFromCmd(cmd)
				dids := args[0]
				device_id, err := strconv.ParseInt(dids, 0, 64)
				if err != nil {
					log.Panicf("incorrect device specification %s", dids)
				}
				cf := fabric.CompressedFabric()
				csf := hex.EncodeToString(cf)
				dids = fmt.Sprintf("%s-%016X", csf, device_id)
				device_filter = strings.ToUpper(dids)
				device_filter = device_filter + "._matter._tcp.local."
			}
			devices := discover.DiscoverComissioned(device, disable_ipv6, device_filter)
			for _, device := range devices {
				if (len(device_filter)) > 0 && device.Name != device_filter {
					continue
				}
				device.Dump()
				fmt.Println()
			}
		},
	}
	var discoverC2Cmd = &cobra.Command{
		Use: "commissionable",
		Run: func(cmd *cobra.Command, args []string) {
			device, _ := cmd.Flags().GetString("interface")
			disable_ipv6, _ := cmd.Flags().GetBool("disable-ipv6")
			qrtext, _ := cmd.Flags().GetString("qr")
			devices := discover.DiscoverAllComissionable(device, disable_ipv6)
			if len(qrtext) > 0 {
				qr := onboarding_payload.DecodeQrText(qrtext)
				devices = filter_devices(devices, qr)
			}
			for _, device := range devices {
				device.Dump()
				fmt.Println()
			}
		},
	}
	discoverC2Cmd.Flags().StringP("qr", "q", "", "qr code")
	discoverCmd.AddCommand(discoverCCmd)
	discoverCmd.AddCommand(discoverC2Cmd)
	discoverCmd.AddCommand(discoverC3Cmd)
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

	rootCmd.AddCommand(cacreateuserCmd)
	rootCmd.AddCommand(cabootCmd)
	rootCmd.AddCommand(commissionCmd)
	rootCmd.AddCommand(discoverCmd)
	rootCmd.AddCommand(decodeQrCmd)
	rootCmd.AddCommand(decodeManualCmd)
	rootCmd.AddCommand(printInfoCmd)
	rootCmd.Execute()
}
