package handler

import (
	"encoding/binary"
	"net/netip"
)

func FormatIP(ipNum uint32) string {
	var bytes [4]byte
	// If you are on x86, the uint32 is stored LittleEndian in RAM
	binary.LittleEndian.PutUint32(bytes[:], ipNum)
	return netip.AddrFrom4(bytes).String()
}

func Int8ToString(array [16]int8) string {
	result := make([]byte, 0, 16)
	for _, caracter := range array {
		if caracter == 0 {
			break
		}
		result = append(result, byte(caracter))
	}
	return string(result)
}
