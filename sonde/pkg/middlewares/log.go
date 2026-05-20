package middlewares

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/dstm45/block-x/sonde/pkg/utils"
)

type CustomWriter struct {
	http.ResponseWriter
	Status int
}

func (cw *CustomWriter) WriteHeader(status int) {
	cw.Status = status
	cw.ResponseWriter.WriteHeader(status)
}

func Logger(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cw := &CustomWriter{
			ResponseWriter: w,
			Status:         http.StatusOK,
		}
		start := time.Now()
		ctx := context.WithValue(r.Context(), utils.LoggerKey, logger)
		defer func() {
			logger.Info("http request", "method", r.Method, "route", r.URL.String(), "status", cw.Status, "latency", fmt.Sprintf("%d ms", time.Since(start).Milliseconds()))
		}()
		next.ServeHTTP(cw, r.WithContext(ctx))
	})
}
