package cluster

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	stdstrings "strings"
)

const gib = 1 << 30

var architectures = map[string]string{"arm64": "arm64", "amd64": "amd64"}

func readText(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return stdstrings.Trim(string(data), "\x00\n ")
}

func memoryGiB(root string) int {
	for _, line := range stdstrings.Split(readText(filepath.Join(root, "proc/meminfo")), "\n") {
		if stdstrings.HasPrefix(line, "MemTotal:") {
			fields := stdstrings.Fields(line)
			if len(fields) > 1 {
				var kib float64
				for _, digit := range fields[1] {
					kib = kib*10 + float64(digit-'0')
				}
				return int(math.RoundToEven(kib * 1024 / gib))
			}
		}
	}
	return 0
}

func disks(root string) map[string]int64 {
	found := map[string]int64{}
	entries, err := os.ReadDir(filepath.Join(root, "sys/block"))
	if err != nil {
		return found
	}
	for _, entry := range entries {
		name := entry.Name()
		skip := false
		for _, prefix := range []string{"loop", "ram", "zram", "dm-", "md", "nbd", "sr"} {
			if stdstrings.HasPrefix(name, prefix) {
				skip = true
			}
		}
		if skip {
			continue
		}
		var sectors int64
		for _, digit := range readText(filepath.Join(root, "sys/block", name, "size")) {
			if digit < '0' || digit > '9' {
				sectors = 0
				break
			}
			sectors = sectors*10 + int64(digit-'0')
		}
		found[name] = sectors * 512
	}
	return found
}

func rootDisk(root string) string {
	present := disks(root)
	for _, line := range stdstrings.Split(readText(filepath.Join(root, "proc/self/mountinfo")), "\n") {
		fields := stdstrings.Fields(line)
		if len(fields) > 9 && fields[4] == "/usr" {
			separator := -1
			for index, field := range fields {
				if field == "-" {
					separator = index
				}
			}
			if separator < 0 || separator+2 >= len(fields) {
				continue
			}
			name := stdstrings.TrimPrefix(fields[separator+2], "/dev/")
			names := make([]string, 0, len(present))
			for disk := range present {
				names = append(names, disk)
			}
			sort.Strings(names)
			for _, disk := range names {
				if name == disk || stdstrings.HasPrefix(name, disk) {
					return disk
				}
			}
		}
	}
	return ""
}

func board(root string) string {
	model := stdstrings.ToLower(readText(filepath.Join(root, "proc/device-tree/model")))
	words := stdstrings.FieldsFunc(model, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') })
	if len(words) == 0 {
		return "unknown"
	}
	return stdstrings.Join(words, "-")
}

func CollectFacts(root string) Obj {
	present := disks(root)
	system := rootDisk(root)
	var largest int64
	for name, size := range present {
		if name != system && size > largest {
			largest = size
		}
	}
	architecture := architectures[runtime.GOARCH]
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	_, tpmErr := os.Stat(filepath.Join(root, "dev/tpmrm0"))
	return Obj{
		"arch":       architecture,
		"memory-gib": memoryGiB(root),
		"disk-gib":   int(math.RoundToEven(float64(largest) / gib)),
		"cpu-count":  runtime.NumCPU(),
		"board":      board(root),
		"tpm":        tpmErr == nil,
	}
}
