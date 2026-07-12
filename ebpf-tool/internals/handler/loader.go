// Package handler est chargé de contenir les toutes les fonctions utilitaires
package handler

import (
	"github.com/cilium/ebpf/link"
	"github.com/dstm45/block-x/ebpf-tool/build"
)

func Load() (*build.MainObjects, []link.Link, error) {
	var obj build.MainObjects
	if err := build.LoadMainObjects(&obj, nil); err != nil {
		return nil, nil, err
	}
	var links []link.Link

	l, err := link.Tracepoint("syscalls", "sys_enter_openat", obj.DetectFileOpening, nil)
	if err != nil {
		return nil, nil, err
	}
	links = append(links, l)

	l, err = link.Tracepoint("syscalls", "sys_exit_openat", obj.CheckIfFileExists, nil)
	if err != nil {
		return nil, nil, err
	}
	links = append(links, l)

	l, err = link.AttachLSM(link.LSMOptions{Program: obj.GetPath})
	if err != nil {
		return nil, nil, err
	}
	links = append(links, l)

	l, err = link.Tracepoint("syscalls", "sys_enter_socket", obj.DetectSocketOpening, nil)
	if err != nil {
		return nil, nil, err
	}
	links = append(links, l)

	l, err = link.Tracepoint("syscalls", "sys_enter_connect", obj.DetectSocketConnect, nil)
	if err != nil {
		return nil, nil, err
	}
	links = append(links, l)

	l, err = link.Tracepoint("syscalls", "sys_enter_dup2", obj.DetectFileRedirection, nil)
	if err != nil {
		return nil, nil, err
	}
	links = append(links, l)

	l, err = link.Tracepoint("syscalls", "sys_enter_execve", obj.DetectProgramExecution, nil)
	if err != nil {
		return nil, nil, err
	}
	links = append(links, l)

	return &obj, links, nil
}
