package ebpfutils

import (
	"path/filepath"

	"github.com/dstm45/block-x/ebpf-tool/build"
	"github.com/dstm45/block-x/ebpf-tool/internals/handler"
)

func StringToInt8Array256(s string) [256]int8 {
	var res [256]int8
	for i := 0; i < len(s) && i < 255; i++ {
		res[i] = int8(s[i])
	}
	return res
}

func StringToInt8Array64(s string) [64]int8 {
	var res [64]int8
	for i := 0; i < len(s) && i < 63; i++ {
		res[i] = int8(s[i])
	}
	return res
}

func TranslatePolicy(p *handler.Policy) *build.MainPolicy {
	ebpfPolicy := &build.MainPolicy{}
	ebpfPolicy.Name = StringToInt8Array64(p.Name)
	ebpfPolicy.Description = StringToInt8Array64(p.Description)

	// Translate Restricted Files
	idx := 0
	for _, fp := range p.RestrictedFiles {
		for _, path := range fp.Paths {
			if idx >= 4 {
				break
			}
			ebpfPolicy.RestrictedFiles[idx].Path = StringToInt8Array64(path)

			// Read Access
			if fp.Read.Allow != nil {
				ebpfPolicy.RestrictedFiles[idx].Read.HasAllow = 1
				perms := fp.Read.Allow
				ebpfPolicy.RestrictedFiles[idx].Read.Allow.UserUidCount = uint32(len(perms.UserUID))
				for k, uid := range perms.UserUID {
					if k >= 4 {
						break
					}
					ebpfPolicy.RestrictedFiles[idx].Read.Allow.UserUid[k] = uint32(uid)
				}
				ebpfPolicy.RestrictedFiles[idx].Read.Allow.BinaryPathsCount = uint32(len(perms.BinaryPaths))
				for k, bpath := range perms.BinaryPaths {
					if k >= 4 {
						break
					}
					ebpfPolicy.RestrictedFiles[idx].Read.Allow.BinaryPaths[k] = StringToInt8Array64(filepath.Base(bpath))
				}
			}

			// Write Access
			if fp.Write.Allow != nil {
				ebpfPolicy.RestrictedFiles[idx].Write.HasAllow = 1
				perms := fp.Write.Allow
				ebpfPolicy.RestrictedFiles[idx].Write.Allow.UserUidCount = uint32(len(perms.UserUID))
				for k, uid := range perms.UserUID {
					if k >= 4 {
						break
					}
					ebpfPolicy.RestrictedFiles[idx].Write.Allow.UserUid[k] = uint32(uid)
				}
				ebpfPolicy.RestrictedFiles[idx].Write.Allow.BinaryPathsCount = uint32(len(perms.BinaryPaths))
				for k, bpath := range perms.BinaryPaths {
					if k >= 4 {
						break
					}
					ebpfPolicy.RestrictedFiles[idx].Write.Allow.BinaryPaths[k] = StringToInt8Array64(filepath.Base(bpath))
				}
			}
			idx++
		}
	}
	ebpfPolicy.RestrictedFilesCount = uint32(idx)

	// Translate Restricted Directories
	dirIdx := 0
	for _, dp := range p.RestrictedDirectories {
		for _, path := range dp.Paths {
			if dirIdx >= 4 {
				break
			}
			ebpfPolicy.RestrictedDirectories[dirIdx].Path = StringToInt8Array64(path)

			// Read Access
			if dp.Read.Allow != nil {
				ebpfPolicy.RestrictedDirectories[dirIdx].Read.HasAllow = 1
				perms := dp.Read.Allow
				ebpfPolicy.RestrictedDirectories[dirIdx].Read.Allow.UserUidCount = uint32(len(perms.UserUID))
				for k, uid := range perms.UserUID {
					if k >= 4 {
						break
					}
					ebpfPolicy.RestrictedDirectories[dirIdx].Read.Allow.UserUid[k] = uint32(uid)
				}
				ebpfPolicy.RestrictedDirectories[dirIdx].Read.Allow.BinaryPathsCount = uint32(len(perms.BinaryPaths))
				for k, bpath := range perms.BinaryPaths {
					if k >= 4 {
						break
					}
					ebpfPolicy.RestrictedDirectories[dirIdx].Read.Allow.BinaryPaths[k] = StringToInt8Array64(filepath.Base(bpath))
				}
			}

			// Write Access
			if dp.Write.Allow != nil {
				ebpfPolicy.RestrictedDirectories[dirIdx].Write.HasAllow = 1
				perms := dp.Write.Allow
				ebpfPolicy.RestrictedDirectories[dirIdx].Write.Allow.UserUidCount = uint32(len(perms.UserUID))
				for k, uid := range perms.UserUID {
					if k >= 4 {
						break
					}
					ebpfPolicy.RestrictedDirectories[dirIdx].Write.Allow.UserUid[k] = uint32(uid)
				}
				ebpfPolicy.RestrictedDirectories[dirIdx].Write.Allow.BinaryPathsCount = uint32(len(perms.BinaryPaths))
				for k, bpath := range perms.BinaryPaths {
					if k >= 4 {
						break
					}
					ebpfPolicy.RestrictedDirectories[dirIdx].Write.Allow.BinaryPaths[k] = StringToInt8Array64(filepath.Base(bpath))
				}
			}
			dirIdx++
		}
	}
	ebpfPolicy.RestrictedDirectoriesCount = uint32(dirIdx)

	return ebpfPolicy
}
