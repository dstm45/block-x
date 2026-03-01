// Package handler est chargé de contenir les toutes les fonctions utilitaires
package handler

import (
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/dstm45/packet_tracer_ebpf/build"
)

type Loader struct {
	Obj build.MainObjects
}

func Load(iname string) (*Loader, error) {
	iface, err := net.InterfaceByName(iname)
	if err != nil {
		return nil, err
	}
	var obj build.MainObjects
	if err = build.LoadMainObjects(&obj, nil); err != nil {
		return nil, err
	}
	_, err = link.AttachXDP(link.XDPOptions{
		Program:   obj.GetPacket,
		Interface: iface.Index,
	})
	if err != nil {
		return nil, err
	}
	_, err = link.Kprobe("tcp_v4_connect", obj.GetProcessByPacket, nil)
	if err != nil {
		return nil, err
	}
	return &Loader{
		Obj: obj,
	}, nil
}
