package GoBACnet

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
	"unsafe"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
)

var socketPort net.PacketConn
var onceExecute = false
var invokeid uint8 = 255

type BVLCpacket struct {
	recvaddr string
	typet    uint8
	function uint8
	length   uint16
}
type NPDUpacket struct {
	version uint8
	control uint8
}
type APDUpacket struct {
	type_flags     uint8
	invokeId       uint8
	serviceChoice  uint8
	objectIdTag    uint8
	objectId       uint32
	ProperityIdTag uint8
	ProperityId    uint8
	dataStartTag   uint8
	applicationTag uint8

	dataEndTag uint8
}
type requestInfo struct {
	dstaddr     string //"ip:port"
	objectId    uint32 //obTy<<22 | obInst
	ProperityId uint8
	parmName    string
	waitTime    time.Duration
}

func (b *requestInfo) SampleConfig() string {
	return `
	[[inputs.BACnet]]
	[[inputs.BACnet.Properity.Tags]]
	dstaddr = "192.168.5.32:56419"
	objectId = 8388608
	requestInfo.ProperityId = 85
	parmName = "name of parameter"
	waitTime = 500
	
	[[inputs.BACnet.Properity.Tags]]
	dstaddr = "192.168.5.32:56419"
	objectId = 0
	requestInfo.ProperityId = 85
	parmName = "name of parameter"
	waitTime = 500
	`
}

func (b *requestInfo) Description() string {
	return "BACnet Read Properity"
}

func init() {
	// do {
	// 	socketPort, err := net.ListenPacket("udp", ":4788")
	// }while(err!=nil)
	// go GetDataUDP(socketPort)

	inputs.Add("GoBACnet", func() telegraf.Input { return &requestInfo{} })
}

func (b *requestInfo) Gather(acc telegraf.Accumulator) string {
	if onceExecute == false { //from init
		for {
			socketPort, err := net.ListenPacket("udp", ":4788")
			if err != nil {
				break
			}
		}
		go GetDataUDP(socketPort, acc)

		onceExecute = true
	}

	SendReadRequest(socketPort, b.dstaddr, b.objectId, b.ProperityId)
	time.Sleep(time.Duration(b.waitTime * time.Millisecond))
}

func SendReadRequest(pc net.PacketConn, dstadr string, object uint32, properity uint8) {
	if invokeid == 255 {
		invokeid = 0
	} else {
		invokeid++
	}
	var data = [17]uint8{0x81, 0x0a, 0x00, 0x11, 0x01, 0x04, 0x00, 0x05, invokeid, 0x0c, 0x0c, uint8(object >> 24 & 0xff), uint8(object >> 16 & 0xff), uint8(object >> 8 & 0xff), uint8(object & 0xff), 0x19, properity}

	LocalAddr, err := net.ResolveUDPAddr("udp", dstadr)
	if err != nil {
		log.Fatal(err)
	}
	pc.WriteTo(data[:17], LocalAddr)
}

func GetDataUDP(pc net.PacketConn, acc telegraf.Accumulator) {
	for {
		rcvbuf := make([]byte, 1472)
		n, addr, err := pc.ReadFrom(rcvbuf)
		if err != nil || n < 6 {
			continue
		}

		fmt.Printf("%v   ", addr)
		for i := 0; i < n; i++ {
			fmt.Printf("%02x ", rcvbuf[i])
		}
		fmt.Println("")

		var BVLCrcv BVLCpacket
		var NPDUrcv NPDUpacket
		BVLCrcv.recvaddr = fmt.Sprintf("%v", addr)
		BVLCrcv.typet = rcvbuf[0]
		BVLCrcv.function = rcvbuf[1]
		BVLCrcv.length = uint16(rcvbuf[2]<<8 | rcvbuf[3])
		NPDUrcv.version = rcvbuf[4]
		NPDUrcv.control = rcvbuf[5]

		if (BVLCrcv.recvaddr != requestInfo.dstaddr) || (BVLCrcv.typet != 0x81) || (BVLCrcv.function != 0x0a) || (BVLCrcv.length != uint16(n)) || (NPDUrcv.version != 1) || (NPDUrcv.control != 0) {
			continue
		}

		go DecodeAPDU(rcvbuf[:n], acc)
	}
}

func DecodeAPDU(buf []uint8, acc telegraf.Accumulator) {
	var APDUrcv APDUpacket
	var count uint8 = 6
	var data_length uint8 = 0
	fields := make(map[string]interface{})
	tags := make(map[string]string)
	APDUrcv.type_flags = buf[count]
	count++
	APDUrcv.invokeId = buf[count]
	count++
	APDUrcv.serviceChoice = buf[count]
	count++
	APDUrcv.objectIdTag = buf[count]
	count++
	APDUrcv.objectId = uint32(uint32(buf[count])<<24 | uint32(buf[count+1])<<16 | uint32(buf[count+2])<<8 | uint32(buf[count+3]))
	count += 4
	APDUrcv.ProperityIdTag = buf[count]
	count++
	APDUrcv.ProperityId = buf[count]
	count++
	APDUrcv.dataStartTag = buf[count]
	count++
	APDUrcv.applicationTag = buf[count]
	count++

	if (APDUrcv.type_flags != 0x30) || (APDUrcv.invokeId != invokeid) || (APDUrcv.serviceChoice != 0x0c) || (APDUrcv.objectIdTag != 0x0c) || (APDUrcv.objectId != requestInfo.objectId) || (APDUrcv.ProperityIdTag != 0x19) || (APDUrcv.ProperityId != requestInfo.ProperityId) || (APDUrcv.dataStartTag != 0x3e) || (APDUrcv.applicationTag&0x08 != 0) {
		return
	}

	if (APDUrcv.applicationTag & 0x07) < 5 {
		data_length = APDUrcv.applicationTag & 0x07
	} else if APDUrcv.applicationTag&0x07 == 5 {
		data_length = buf[count]
		count++
	} else {
		return
	}

	switch APDUrcv.applicationTag >> 4 {
	case 1: //bool
		if buf[count] != 0x3f {
			return
		}
		fields["DeviceAddress"] = requestInfo.dstaddr
		if data_length == 0 {
			tags[requestInfo.parmName] = false
			//fmt.Println(requestInfo.parmName, ": ", "false")
		} else {
			tags[requestInfo.parmName] = true
			//fmt.Println(requestInfo.parmName, ": ", "true")
		}
		acc.AddFields("GoBACnet", fields, tags)
		break
	case 2: //unsigned int
		var data_uint uint64 = 0
		for i := 0; i < int(data_length); i++ {
			data_uint = ((data_uint << 8) | uint64(buf[count]))
			count += 1
		}
		if buf[count] != 0x3f {
			return
		}
		fields["DeviceAddress"] = requestInfo.dstaddr
		tags[requestInfo.parmName] = data_uint
		acc.AddFields("GoBACnet", fields, tags)
		//fmt.Println(requestInfo.parmName, ": ", data_uint)
		break
	case 4: //real
		if data_length == 4 { //float
			data_arr := []byte{buf[count], buf[count+1], buf[count+2], buf[count+3]}
			count += 4
			if buf[count] != 0x3f {
				return
			}
			data_int := binary.BigEndian.Uint32(data_arr)
			data_float := *(*float32)(unsafe.Pointer(&data_int))
			fields["DeviceAddress"] = requestInfo.dstaddr
			tags[requestInfo.parmName] = data_float
			acc.AddFields("GoBACnet", fields, tags)
			// fmt.Println(requestInfo.parmName, ": ", data_float)
		} else if data_length == 8 { //double
			data_arr := []byte{buf[count], buf[count+1], buf[count+2], buf[count+3], buf[count+4], buf[count+5], buf[count+6], buf[count+7]}
			count += 8
			if buf[count] != 0x3f {
				return
			}
			data_int := binary.BigEndian.Uint64(data_arr)
			data_float := *(*float64)(unsafe.Pointer(&data_int))
			fields["DeviceAddress"] = requestInfo.dstaddr
			tags[requestInfo.parmName] = data_float
			acc.AddFields("GoBACnet", fields, tags)
			// fmt.Println(requestInfo.parmName, ": ", data_float)
		}
		break
	case 7: //string.
		var RxString [256]string
		for i := 0; i < int(data_length); i++ {
			RxString[i] = string(buf[count])
			RxString[i+1] = string(0)
			count += 1
		}
		if buf[count] != 0x3f {
			return
		}
		fields["DeviceAddress"] = requestInfo.dstaddr
		tags[requestInfo.parmName] = RxString
		acc.AddFields("GoBACnet", fields, tags)
		//fmt.Println(requestInfo.parmName, ": ", RxString)
		break
	default: //other
		return
	}
}
