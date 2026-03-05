package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/dstm45/block-x/build"
	"github.com/dstm45/block-x/internals/handler"
)

func main() {
	// configuration := config.LoadConfig()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("Erreur lors de la modification de la locked memory. err:", err)
	}
	loader, err := handler.Load()
	if err != nil {
		log.Fatalln("erreur au niveau du loader. err:", err)
	}
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var key uint32
			var value build.MainDataT
			iterator := loader.Datatable.Iterate()
			for iterator.Next(&key, &value) {
				fmt.Println("chemin du fichier:", handler.Int8ToString(value.Filepath[:]))
				fmt.Println("uid utilisateur:", value.Uid)
				fmt.Println("Nom du processus:", handler.Int8ToString(value.ProcessName[:]))
				fmt.Println("=============================")
				loader.Datatable.Delete(&key)
			}
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
