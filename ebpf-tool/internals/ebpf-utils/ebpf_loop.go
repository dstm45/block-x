package ebpfutils

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/dstm45/block-x/ebpf-tool/build"
	"github.com/dstm45/block-x/ebpf-tool/internals/config"
	"github.com/dstm45/block-x/ebpf-tool/internals/database"
	"github.com/jackc/pgx/v5/pgtype"
)

func Run(ctx context.Context, configuration config.Config, loader *build.MainObjects, query *database.Queries) {
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
					Comm: Int8ToString(value.ProcessName[:]),
					Timestamp: pgtype.Timestamptz{
						Time:  time.Now(),
						Valid: true,
					},
				}
				logs = append(logs, newLog)
				if len(logs) == configuration.LogBatchNumber {
					query.SaveLogs(ctx, logs)
					logs = make([]database.SaveLogsParams, 0)
				}
				fmt.Println("chemin du fichier:", Int8ToString(value.Filepath[:]))
				fmt.Println("uid utilisateur:", value.Uid)
				fmt.Println("Nom du processus:", Int8ToString(value.ProcessName[:]))

				fmt.Println("=============================")
				loader.Datatable.Delete(&key)
			}
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
