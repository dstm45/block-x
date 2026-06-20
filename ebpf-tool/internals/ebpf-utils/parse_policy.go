package ebpfutils

import (
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

func TranslatePolicy(p *handler.Policy) *build.MainPolicy {
	ebpfPolicy := &build.MainPolicy{}
	ebpfPolicy.Name = StringToInt8Array256(p.Name)
	ebpfPolicy.Description = StringToInt8Array256(p.Description)

	// Translate Restricted Files
	for i, fp := range p.RestrictedFiles {
		if i >= 16 {
			break
		}
		ebpfPolicy.RestrictedFiles[i].PathsCount = uint32(len(fp.Paths))
		for j, path := range fp.Paths {
			if j >= 16 {
				break
			}
			ebpfPolicy.RestrictedFiles[i].Paths[j] = StringToInt8Array256(path)
		}

		// Read Access
		if fp.Read.Allow != nil {
			ebpfPolicy.RestrictedFiles[i].Read.HasAllow = 1
			perms := fp.Read.Allow
			ebpfPolicy.RestrictedFiles[i].Read.Allow.UserUidCount = uint32(len(perms.UserUID))
			for k, uid := range perms.UserUID {
				if k >= 16 {
					break
				}
				ebpfPolicy.RestrictedFiles[i].Read.Allow.UserUid[k] = uint32(uid)
			}
			ebpfPolicy.RestrictedFiles[i].Read.Allow.BinaryPathsCount = uint32(len(perms.BinaryPaths))
			for k, path := range perms.BinaryPaths {
				if k >= 16 {
					break
				}
				ebpfPolicy.RestrictedFiles[i].Read.Allow.BinaryPaths[k] = StringToInt8Array256(path)
			}
		}

		// Write Access
		if fp.Write.Allow != nil {
			ebpfPolicy.RestrictedFiles[i].Write.HasAllow = 1
			perms := fp.Write.Allow
			ebpfPolicy.RestrictedFiles[i].Write.Allow.UserUidCount = uint32(len(perms.UserUID))
			for k, uid := range perms.UserUID {
				if k >= 16 {
					break
				}
				ebpfPolicy.RestrictedFiles[i].Write.Allow.UserUid[k] = uint32(uid)
			}
			ebpfPolicy.RestrictedFiles[i].Write.Allow.BinaryPathsCount = uint32(len(perms.BinaryPaths))
			for k, path := range perms.BinaryPaths {
				if k >= 16 {
					break
				}
				ebpfPolicy.RestrictedFiles[i].Write.Allow.BinaryPaths[k] = StringToInt8Array256(path)
			}
		}
		ebpfPolicy.RestrictedFilesCount = uint32(i + 1)
	}

	// Translate Restricted Directories
	for i, dp := range p.RestrictedDirectories {
		if i >= 16 {
			break
		}
		ebpfPolicy.RestrictedDirectories[i].PathsCount = uint32(len(dp.Paths))
		for j, path := range dp.Paths {
			if j >= 16 {
				break
			}
			ebpfPolicy.RestrictedDirectories[i].Paths[j] = StringToInt8Array256(path)
		}

		// Read Access
		if dp.Read.Allow != nil {
			ebpfPolicy.RestrictedDirectories[i].Read.HasAllow = 1
			perms := dp.Read.Allow
			ebpfPolicy.RestrictedDirectories[i].Read.Allow.UserUidCount = uint32(len(perms.UserUID))
			for k, uid := range perms.UserUID {
				if k >= 16 {
					break
				}
				ebpfPolicy.RestrictedDirectories[i].Read.Allow.UserUid[k] = uint32(uid)
			}
			ebpfPolicy.RestrictedDirectories[i].Read.Allow.BinaryPathsCount = uint32(len(perms.BinaryPaths))
			for k, path := range perms.BinaryPaths {
				if k >= 16 {
					break
				}
				ebpfPolicy.RestrictedDirectories[i].Read.Allow.BinaryPaths[k] = StringToInt8Array256(path)
			}
		}

		// Write Access
		if dp.Write.Allow != nil {
			ebpfPolicy.RestrictedDirectories[i].Write.HasAllow = 1
			perms := dp.Write.Allow
			ebpfPolicy.RestrictedDirectories[i].Write.Allow.UserUidCount = uint32(len(perms.UserUID))
			for k, uid := range perms.UserUID {
				if k >= 16 {
					break
				}
				ebpfPolicy.RestrictedDirectories[i].Write.Allow.UserUid[k] = uint32(uid)
			}
			ebpfPolicy.RestrictedDirectories[i].Write.Allow.BinaryPathsCount = uint32(len(perms.BinaryPaths))
			for k, path := range perms.BinaryPaths {
				if k >= 16 {
					break
				}
				ebpfPolicy.RestrictedDirectories[i].Write.Allow.BinaryPaths[k] = StringToInt8Array256(path)
			}
		}
		ebpfPolicy.RestrictedDirectoriesCount = uint32(i + 1)
	}

	return ebpfPolicy
}
