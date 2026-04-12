package main

import (
	"context"
	"log"

	"github.com/cilium/ebpf/rlimit"
	"github.com/dstm45/block-x/ebpf-tool/internals/config"
	"github.com/dstm45/block-x/ebpf-tool/internals/database"
	ebpfutils "github.com/dstm45/block-x/ebpf-tool/internals/ebpf-utils"
	"github.com/dstm45/block-x/ebpf-tool/internals/handler"
)

func main() {
	configuration := config.LoadConfig()
	ctx := context.Background()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("Erreur lors de la modification de la locked memory. err:", err)
	}
	pool, err := database.Connection(ctx, configuration)
	if err != nil {
		log.Fatalln("Erreur lors de la connection à la base de données. err:", err)
	}
	query := database.New(pool)
	loader, err := handler.Load()
	if err != nil {
		log.Fatalln("erreur au niveau du loader. err:", err)
	}
	ebpfutils.Run(ctx, *configuration, loader, query)
}
