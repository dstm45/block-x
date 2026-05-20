package utils

import (
	"context"
	"log/slog"
)

type CtxKey string

const LoggerKey CtxKey = "logger"

func GetLoggerFromContext(ctx context.Context) *slog.Logger {
	logger, ok := ctx.Value(LoggerKey).(*slog.Logger)
	if !ok {
		return slog.Default() // Return a default logger if not found to prevent panic
	}
	return logger
}
