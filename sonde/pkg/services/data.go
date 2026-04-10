// Package services ocntrains all the services.
package services

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/dstm45/block-x/sonde/pkg/database"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

type IDataService interface {
	Save(ctx context.Context, params database.SaveMetricsParams) error
	Gather(ctx context.Context) (*database.SaveMetricsParams, error)
}

type DataService struct {
	queries *database.Queries
}

func NewDataService(q *database.Queries) IDataService {
	service := DataService{
		queries: q,
	}
	return &service
}

func (ds DataService) Gather(ctx context.Context) (*database.SaveMetricsParams, error) {
	server, err := host.Info()
	if err != nil {
		return nil, err
	}
	fmt.Printf("Host: %s | OS: %s | Uptime: %d hrs\n", server.Hostname, server.OS, server.Uptime/3600)

	// We wait 1 second to get an accurate measurement
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return nil, err
	}

	fmt.Printf("CPU Usage: %.2f%%\n", cpuPercent[0])

	memory, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}
	fmt.Printf("Memory: %vMB / %vMB (%.2f%% used)\n", memory.Used/1024/1024, memory.Total/1024/1024, memory.UsedPercent)

	storage, err := disk.Usage("/")
	if err != nil {
		return nil, err
	}
	fmt.Printf("Disk (/): %vGB Free of %vGB\n", storage.Free/1024/1024/1024, storage.Total/1024/1024/1024)

	internet, err := net.IOCounters(false)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Net: Sent %v MB | Recv %v MB\n", internet[0].BytesSent/1024/1024, internet[0].BytesRecv/1024/1024)
	params := database.SaveMetricsParams{
		Timestamp: pgtype.Timestamptz{
			Time:  time.Now(),
			Valid: true,
		},
		Hostname:          server.Hostname,
		Os:                server.OS,
		UptimeSeconds:     int64(server.Uptime),
		CpuUsagePercent:   pgtype.Numeric{Int: big.NewInt(int64(cpuPercent[0])), Valid: true},
		MemoryUsedPercent: pgtype.Numeric{Int: big.NewInt(int64(memory.UsedPercent)), Valid: true},
		MemoryTotalBytes:  int64(memory.Total / 1024 / 1024),
		MemoryUsedBytes:   int64(memory.Used / 1024 / 1024),
		DiskTotalBytes:    int64(storage.Total / 1024 / 1024 / 1024),
		DiskFreeBytes:     int64(storage.Free / 1024 / 1024 / 1024),
		NetworkBytesRecv:  int64(internet[0].BytesRecv / 1024 / 1024),
		NetworkBytesSent:  int64(internet[0].BytesSent / 1024 / 1024),
	}

	return &params, nil
}

func (ds DataService) Save(ctx context.Context, params database.SaveMetricsParams) error {
	err := ds.queries.SaveMetrics(ctx, params)
	return err
}
