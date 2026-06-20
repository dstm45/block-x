/*
Package build est chargé de contenir les scripts de compilation du code c
et contenir les fichiers go resultants
*/
package build

//go:generate go tool bpf2go -tags linux -target amd64 -type Policy main ../internals/ebpf/main.ebpf.c
