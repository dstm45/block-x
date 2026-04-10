package main

import (
	"context"
	"log"
	"log/slog"
	"os"

	"github.com/dstm45/block-x/sonde/pkg/api"
	"github.com/dstm45/block-x/sonde/pkg/config"
	"github.com/dstm45/block-x/sonde/pkg/controllers"
	"github.com/dstm45/block-x/sonde/pkg/database"
	"github.com/dstm45/block-x/sonde/pkg/services"
)

func main() {
	configuration := config.LoadConfig()
	ctx := context.Background()
	Pool, err := database.Connection(ctx, configuration)
	if err != nil {
		log.Fatalln("Impossible d'accéder à la base de données.", err)
	}
	queries := database.New(Pool)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	dataService := services.NewDataService(queries)
	dataController := controllers.NewDataController(dataService)
	API := api.NewAPI(*dataController)
	server, err := api.NewServer(configuration, API, logger)
	if err != nil {
		log.Fatalln(err)
	}
	log.Fatalln(server.Start())
}
