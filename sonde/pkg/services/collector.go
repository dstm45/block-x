// Package services contains all the services.
package services

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

type ICollectionService interface {
	Gather() error
	GetRegistry() *prometheus.Registry
}

type CollectionService struct {
	Reg          *prometheus.Registry
	cpuPercent   prometheus.Gauge
	uptime       prometheus.Gauge
	memoryUsed   prometheus.Gauge
	memoryTotal  prometheus.Gauge
	storageUsed  prometheus.Gauge
	storageTotal prometheus.Gauge
	networkRecv  prometheus.Gauge
	networkSent  prometheus.Gauge
	hostInfo     *prometheus.GaugeVec
}

func NewCollectionService(reg *prometheus.Registry) ICollectionService {
	s := &CollectionService{
		Reg: reg,
		cpuPercent: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cpu_usage_percent",
			Help: "Current CPU usage in percent",
		}),
		uptime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "uptime_seconds",
			Help: "System uptime in seconds",
		}),
		memoryTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "memory_total_bytes",
			Help: "Total system memory in bytes",
		}),
		memoryUsed: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "memory_used_bytes",
			Help: "Used system memory in bytes",
		}),
		storageTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "storage_total_bytes",
			Help: "Total storage space in bytes",
		}),
		storageUsed: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "storage_used_bytes",
			Help: "Used storage space in bytes",
		}),
		networkRecv: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "network_receive_bytes_total",
			Help: "Total bytes received over network",
		}),
		networkSent: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "network_transmit_bytes_total",
			Help: "Total bytes sent over network",
		}),
		hostInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "host_info",
			Help: "Static host information",
		}, []string{"hostname", "os"}),
	}

	reg.MustRegister(
		s.cpuPercent,
		s.uptime,
		s.memoryTotal,
		s.memoryUsed,
		s.storageTotal,
		s.storageUsed,
		s.networkRecv,
		s.networkSent,
		s.hostInfo,
	)

	return s
}

func (s *CollectionService) GetRegistry() *prometheus.Registry {
	return s.Reg
}

func (s *CollectionService) Gather() error {
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return err
	}
	s.cpuPercent.Set(cpuPercent[0])

	server, err := host.Info()
	if err != nil {
		return err
	}
	s.uptime.Set(float64(server.Uptime))
	s.hostInfo.WithLabelValues(server.Hostname, server.OS).Set(1)

	memory, err := mem.VirtualMemory()
	if err != nil {
		return err
	}
	s.memoryTotal.Set(float64(memory.Total))
	s.memoryUsed.Set(float64(memory.Used))

	storage, err := disk.Usage("/")
	if err != nil {
		return err
	}
	s.storageTotal.Set(float64(storage.Total))
	s.storageUsed.Set(float64(storage.Used))

	internet, err := net.IOCounters(false)
	if err != nil {
		return err
	}
	if len(internet) > 0 {
		s.networkRecv.Set(float64(internet[0].BytesRecv))
		s.networkSent.Set(float64(internet[0].BytesSent))
	}

	return nil
}
