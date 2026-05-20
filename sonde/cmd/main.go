package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/dstm45/block-x/sonde/pkg/api"
	"github.com/dstm45/block-x/sonde/pkg/config"
	"github.com/dstm45/block-x/sonde/pkg/controllers"
	"github.com/dstm45/block-x/sonde/pkg/services"
	"github.com/prometheus/client_golang/prometheus"
)

func main() {
	configuration := config.LoadConfig()
	ctx := context.Background()

	reg := prometheus.NewRegistry()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	dataService := services.NewCollectionService(reg)
	dataController := controllers.NewCollectionController(dataService)

	// Start background worker to gather metrics every minute
	go func() {
		ticker := time.NewTicker(time.Second * 5)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				err := dataService.Gather()
				if err != nil {
					logger.Error("Failed to gather metrics", "error", err)
					continue
				}
			}
		}
	}()

	API := api.NewAPI(*dataController)
	server, err := api.NewServer(configuration, API, logger)
	if err != nil {
		log.Fatalln(err)
	}
	log.Fatalln(server.Start())
}
