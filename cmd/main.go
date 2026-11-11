package main

import (
	"context"
	"log"

	"github.com/cilium/ebpf/rlimit"
	ebpftool "github.com/dstm45/block_x/cmd/ebpf-tool"
	"github.com/dstm45/block_x/pkg/config"
	"github.com/dstm45/block_x/pkg/database"
)

type ressources struct {
	ctx           context.Context
	configuration *config.Config
	query         *database.Queries
}

func newRessource() *ressources {
	configuration := config.LoadConfig()
	ctx := context.Background()
	pool, err := database.Connection(ctx, configuration)
	if err != nil {
		log.Fatalln("Erreur lors de la connection à la base de données. err:", err)
	}
	query := database.New(pool)
	return &ressources{
		ctx,
		configuration,
		query,
	}
}

func Initialize() {}
func main() {
	res := newRessource()
	err := rlimit.RemoveMemlock()
	if err != nil {
		log.Println("Erreur lors de la modification de la locked memory. err:", err)
	}

	ebpfStruct := ebpftool.NewEbpfStruct()
	ebpfStruct.Run(res.ctx, res.configuration, res.query)
}
