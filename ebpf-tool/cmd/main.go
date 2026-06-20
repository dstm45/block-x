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

	// Load and translate policy
	policy := handler.NewPolicy()
	policy.Parse("config.yaml")
	ebpfPolicy := ebpfutils.TranslatePolicy(policy)

	var key uint32 = 0
	if err := loader.PolicyMap.Update(key, ebpfPolicy, 0); err != nil {
		log.Fatalln("Erreur lors du chargement de la police dans l'ebpf. err:", err)
	}

	ebpfutils.Run(ctx, *configuration, loader, query)
}
