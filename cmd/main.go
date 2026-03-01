package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/dstm45/packet_tracer_ebpf/build"
	"github.com/dstm45/packet_tracer_ebpf/internal/handler"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("Erreur lors de la modification de la locked memory. err:", err)
	}
	loader, err := handler.Load("enp1s0")
	if err != nil {
		log.Fatalln("erreur au niveau du loader. err:", err)
	}
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var packetData build.MainPacketData
			var additionnalData build.AdditionalPacketData
			var key uint32 = 0
			err := loader.Obj.PacketMap.Lookup(&key, &packetData)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			err = loader.Obj.ProcessPacket.Lookup(&key, &additionnalData)
			if err != nil {
				log.Fatalln("Echec lors de la recherche d'information dans la map process packet. err:", err)
			}
			if packetData.SourceIpAddress == 0 {
				continue
			}
			fmt.Printf("%s -> %s\n", handler.FormatIP(packetData.SourceIpAddress), handler.FormatIP(packetData.DestinationIpAddress))
			fmt.Printf("process: %s from port:%d\n", handler.Int8ToString(additionnalData.Process), additionnalData.Dport)
			loader.Obj.PacketMap.Update(&key, &build.MainPacketData{SourceIpAddress: 0, DestinationIpAddress: 0}, ebpf.UpdateAny)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
