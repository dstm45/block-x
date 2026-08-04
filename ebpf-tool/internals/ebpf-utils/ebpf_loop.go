package ebpfutils

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/dstm45/block-x/ebpf-tool/build"
	"github.com/dstm45/block-x/ebpf-tool/internals/config"
	"github.com/dstm45/block-x/ebpf-tool/internals/database"
	"github.com/jackc/pgx/v5/pgtype"
)

func Run(ctx context.Context, configuration config.Config, loader *build.MainObjects, query *database.Queries) {
	rd, err := ringbuf.NewReader(loader.LogsRingbuf)
	if err != nil {
		log.Fatalf("erreur lors de l'ouverture du ring buffer reader: %v", err)
	}
	defer rd.Close()

	go func() {
		var event build.MainLog
		for {
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("erreur lors de la lecture du ring buffer: %v", err)
				continue
			}

			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("erreur lors de la désérialisation du log du ring buffer: %v", err)
				continue
			}

			// Resolve process executable path from /proc/<pid>/exe if possible
			comm := Int8ToString(event.Program[:])
			pid := int32(event.Pid)
			exePath := comm
			if pid > 0 {
				if resolved, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
					exePath = resolved
				}
			}

			targetText := pgtype.Text{
				String: Int8ToString(event.Target[:]),
				Valid:  true,
			}

			newLog := database.SaveLogsParams{
				Timestamp: pgtype.Timestamptz{
					Time:  time.Now(),
					Valid: true,
				},
				Uid:         int32(event.Uid),
				Gid:         int32(event.Gid),
				Pid:         pid,
				Ppid:        int32(event.Ppid),
				Comm:        comm,
				Executable:  exePath,
				Tid:         pid,
				Syscall:     int32(event.Syscall),
				Target:      targetText,
				ReturnValue: 0,
				Duration:    0,
			}

			log.Printf("[INFO] Ringbuf Event: uid=%d gid=%d pid=%d ppid=%d comm=%s executable=%s syscall=%d target=%s\n",
				event.Uid, event.Gid, pid, event.Ppid, comm, exePath, event.Syscall, targetText.String)

			_, err = query.SaveLogs(ctx, []database.SaveLogsParams{newLog})
			if err != nil {
				log.Printf("erreur lors de la sauvegarde du log du ring buffer: %v", err)
			}
		}
	}()

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
					Uid:        int32(value.Uid),
					Pid:        int32(value.Pid),
					Ppid:       int32(value.ParentPid),
					Gid:        int32(value.Gid),
					Comm:       Int8ToString(value.ProcessName[:]),
					Executable: Int8ToString(value.Filepath[:]),
					Tid:        int32(value.Pid),
					Syscall:    257, // __NR_openat on x86_64
					Target: pgtype.Text{
						String: Int8ToString(value.Filepath[:]),
						Valid:  true,
					},
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
				log.Printf("[INFO] Datatable Event: uid=%d gid=%d pid=%d ppid=%d comm=%s executable=%s\n",
					value.Uid, value.Gid, value.Pid, value.ParentPid, Int8ToString(value.ProcessName[:]), Int8ToString(value.Filepath[:]))

				loader.Datatable.Delete(&key)
			}
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
