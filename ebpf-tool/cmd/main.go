package main

import (
	"context"
	"fmt"
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
	loader, links, err := handler.Load()
	if err != nil {
		log.Fatalln("erreur au niveau du loader. err:", err)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	// Load and translate policy
	policy := handler.NewPolicy()
	policy.Parse("config.yaml")
	ebpfPolicy := ebpfutils.TranslatePolicy(policy)
	fmt.Printf("Parsed Name: %s\n", ebpfutils.Int8ToString(ebpfPolicy.Name[:]))
	fmt.Printf("Parsed Files Count: %d\n", ebpfPolicy.RestrictedFilesCount)
	for idx := 0; idx < int(ebpfPolicy.RestrictedFilesCount); idx++ {
		fmt.Printf("  File %d Path: %s\n", idx, ebpfutils.Int8ToString(ebpfPolicy.RestrictedFiles[idx].Path[:]))
		fmt.Printf("    Read user UIDs count: %d\n", ebpfPolicy.RestrictedFiles[idx].Read.Allow.UserUidCount)
		fmt.Printf("    Read binary paths count: %d\n", ebpfPolicy.RestrictedFiles[idx].Read.Allow.BinaryPathsCount)
	}

	var key uint32 = 0
	if err := loader.PolicyMap.Update(key, ebpfPolicy, 0); err != nil {
		log.Fatalln("Erreur lors du chargement de la police dans l'ebpf. err:", err)
	}

	ebpfutils.Run(ctx, *configuration, loader, query)
}
