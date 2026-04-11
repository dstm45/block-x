// Package api contains all the configuration for the server
package api

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dstm45/block-x/web/pkg/config"
)

type Server struct {
	Server http.Server
}

func NewServer(configuration *config.Config, api *API, logger *slog.Logger) (*Server, error) {
	mux := api.Routes()
	wrapper := Server{
		Server: http.Server{
			Addr:    fmt.Sprintf("%s:%s", configuration.ServerAddress, configuration.ServerPort),
			Handler: mux, /*middlewares.Logger(middlewares.SetHeader(mux), logger)*/
		},
	}
	return &wrapper, nil
}

func (wrapper *Server) Start() error {
	go func() {
		wrapper.Server.ListenAndServe()
	}()
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := wrapper.Server.Shutdown(ctx)
	log.Println("Extinction du serveur.")
	return err
}
