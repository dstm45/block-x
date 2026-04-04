package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/dstm45/block-x/ebpf-tool/build"
	"github.com/dstm45/block-x/ebpf-tool/internals/config"
	"github.com/dstm45/block-x/ebpf-tool/internals/database"
	"github.com/dstm45/block-x/ebpf-tool/internals/handler"
	"github.com/jackc/pgx/v5/pgtype"
)

func main() {
	configuration := config.LoadConfig()
	ctx := context.Background()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println("Erreur lors de la modification de la locked memory. err:", err)
	}
	pool, err := database.Connection(ctx, configuration)
	if err != nil {
		log.Fatalln("Erreur lors de la connection à la base de données. err:", err)
	}
	query := database.New(pool)
	loader, err := handler.Load()
	if err != nil {
		log.Fatalln("erreur au niveau du loader. err:", err)
	}
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	var logs []database.SaveLogsParams
	for {
		select {
		case <-tick:
			var key uint32
			var value build.MainDataT
			iterator := loader.Datatable.Iterate()
			for iterator.Next(&key, &value) {
				newLog := database.SaveLogsParams{
					Uid:  int32(value.Uid),
					Pid:  int32(value.Pid),
					Ppid: int32(value.ParentPid),
					Gid:  int32(value.Gid),
					Comm: handler.Int8ToString(value.ProcessName[:]),
					Timestamp: pgtype.Timestamptz{
						Time:  time.Now(),
						Valid: true,
					},
				}
				logs = append(logs, newLog)
				if len(logs) == 10 {
					query.SaveLogs(ctx, logs)
					logs = make([]database.SaveLogsParams, 0)
				}
				fmt.Println("chemin du fichier:", handler.Int8ToString(value.Filepath[:]))
				fmt.Println("uid utilisateur:", value.Uid)
				fmt.Println("Nom du processus:", handler.Int8ToString(value.ProcessName[:]))

				fmt.Println("=============================")
				loader.Datatable.Delete(&key)
			}
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
