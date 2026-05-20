package api

import (
	"net/http"

	"github.com/dstm45/block-x/sonde/pkg/controllers"
)

type API struct {
	dataController controllers.CollectionController
}

func NewAPI(dataController controllers.CollectionController) *API {
	return &API{
		dataController: dataController,
	}
}

func (api API) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", api.dataController.GetMetrics)

	return mux
}
