package ebpftool

import (
	"context"
	"io"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/dstm45/block_x/internals/ebpf_tool/build"
	"github.com/dstm45/block_x/internals/ebpf_tool/handler"
	"github.com/dstm45/block_x/internals/ebpf_tool/utils"
	"github.com/dstm45/block_x/pkg/config"
	"github.com/dstm45/block_x/pkg/database"
)

type EbpfStruct struct {
	Loader *build.MainObjects
	Links  []link.Link
	Policy *build.MainPolicy
}

func NewEbpfStruct() *EbpfStruct {
	loader, links, err := handler.Load()
	if err != nil {
		log.Fatalln("erreur au niveau du loader. err:", err)
	}

	policy := handler.NewPolicy()
	policy.Parse("config.yaml")
	ebpfPolicy := utils.TranslatePolicy(policy)

	return &EbpfStruct{
		Loader: loader,
		Links:  links,
		Policy: ebpfPolicy,
	}
}

func (es *EbpfStruct) FreeLinks() {
	for _, l := range es.Links {
		l.Close()
	}
}

func (es *EbpfStruct) LoadPolicy() error {
	var key uint32 = 0
	err := es.Loader.PolicyMap.Update(key, es.Policy, 0)
	if err != nil {
		// log.Fatalln("Erreur lors du chargement de la police dans l'ebpf. err:", err)
		return nil
	}
	return err
}

func startLogging() {
	// Ensure logs directory exists and configure logging to file and console
	if err := os.MkdirAll("logs", 0o755); err != nil {
		log.Println("Warning: could not create logs directory:", err)
	}
	logFile, err := os.OpenFile("logs/app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		log.Println("Warning: could not open log file logs/app.log:", err)
	} else {
		defer logFile.Close()
		mw := io.MultiWriter(os.Stderr, logFile)
		log.SetOutput(mw)
	}
}

func (es *EbpfStruct) Run(ctx context.Context, configuration *config.Config, query *database.Queries) {
	startLogging()
	defer es.FreeLinks()
	utils.Run(ctx, *configuration, es.Loader, query)
}
