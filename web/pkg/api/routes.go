package api

import (
	"net/http"

	"github.com/dstm45/block-x/web/pkg/controllers"
	"github.com/dstm45/block-x/web/pkg/services"
)

type API struct {
	dataService    services.IDataService
	dataController controllers.DataController
}

func NewAPI(dataController controllers.DataController) *API {
	return &API{
		dataController: dataController,
	}
}

func (api API) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /getdata", api.dataController.GetMetrics)
	/*
		mux.HandleFunc("GET /signin", api.dataController.GetMetrics)
		mux.HandleFunc("GET /signup", api.dataController.GetMetrics)
		mux.HandleFunc("GET /newaccount", api.dataController.GetMetrics)
		mux.HandleFunc("GET /display_data", api.dataController.GetMetrics)
	*/
	return mux
}
