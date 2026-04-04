// Package database gère la connexion à la base de données et les requêtes.
package database

import (
	"context"

	"github.com/dstm45/block-x/ebpf-tool/internals/config"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/lib/pq"
)

func Connection(ctx context.Context, configuration *config.Config) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, configuration.DatabaseURI)
	if err != nil {
		return nil, err
	}
	err = pool.Ping(ctx)
	if err != nil {
		return nil, err
	}

	return pool, nil
}
