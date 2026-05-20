// Package controllers contains all the controllers
package controllers

import (
	"net/http"

	"github.com/dstm45/block-x/sonde/pkg/services"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type CollectionController struct {
	service services.ICollectionService
}

func NewCollectionController(service services.ICollectionService) *CollectionController {
	controller := CollectionController{
		service: service,
	}
	return &controller
}

func (c CollectionController) GetMetrics(w http.ResponseWriter, r *http.Request) {
	reg := c.service.GetRegistry()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}).ServeHTTP(w, r)
}
