// Package handler est chargé de contenir les toutes les fonctions utilitaires
package handler

import (
	"github.com/cilium/ebpf/link"
	"github.com/dstm45/block-x/build"
)

func Load() (*build.MainObjects, error) {
	var obj build.MainObjects
	if err := build.LoadMainObjects(&obj, nil); err != nil {
		return nil, err
	}
	_, err := link.Tracepoint("syscalls", "sys_enter_openat", obj.DetectFileOpening, nil)
	if err != nil {
		return nil, err
	}
	_, err = link.Tracepoint("syscalls", "sys_exit_openat", obj.CheckIfFileExists, nil)
	if err != nil {
		return nil, err
	}
	_, err = link.AttachLSM(link.LSMOptions{Program: obj.GetPath})
	if err != nil {
		return nil, err
	}
	return &obj, nil
}
