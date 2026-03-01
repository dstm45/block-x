/*
Package build est chargé de contenir les scripts de compilation du code c
et contenir les fichiers go resultants
*/
package build

//go:generate go tool bpf2go -tags linux -target amd64 main ../internal/ebpf/main.ebpf.c
