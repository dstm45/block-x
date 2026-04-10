// Package controllers contains all the controllers
package controllers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/dstm45/block-x/sonde/pkg/services"
)

type DataController struct {
	service services.IDataService
}

func NewDataController(service services.IDataService) *DataController {
	controller := DataController{
		service: service,
	}
	return &controller
}

func (c DataController) GetMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	data, err := c.service.Gather(ctx)
	if err != nil {
		log.Println("Erreur lors du rassemblement des données")
	}
	err = json.NewEncoder(w).Encode(&data)
	if err != nil {
		log.Println("Erreur lors de l'encodage des données")
	}
	err = c.service.Save(ctx, *data)
	if err != nil {
		log.Println("Erreur lors de l'enregistrement des performances dans la base de données. err:", err)
	}
}
