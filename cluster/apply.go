package cluster

import (
	"os"
	"os/exec"
	"path/filepath"
	stdstrings "strings"
)

func writeIfChanged(path, content string, mode os.FileMode) (bool, error) {
	if existing, err := os.ReadFile(path); err == nil && string(existing) == content {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	return true, writeAtomic(path, []byte(content), mode)
}

func removeFile(path string) bool { return os.Remove(path) == nil }

type Host interface {
	Run(name string, arguments ...string)
}

type SystemHost struct{}

func (SystemHost) Run(name string, arguments ...string) {
	_ = exec.Command(name, arguments...).Run()
}

func hostPath(root, run, path string) string {
	if stdstrings.HasPrefix(path, runPrefix) {
		return filepath.Join(run, stdstrings.TrimPrefix(path, runPrefix))
	}
	return filepath.Join(root, path)
}

func Apply(view *View, files []FileSpec, root, runDirectory string, host Host) ([]string, error) {
	var changed []string
	state := Marshal(Obj{"slot": view.Slot, "rank": view.Rank, "members": view.Members, "roles": view.Roles, "topology": view.Topology})
	if _, err := writeIfChanged(filepath.Join(runDirectory, "state.json"), string(state)+"\n", 0o644); err != nil {
		return changed, err
	}
	markers := filepath.Join(root, "etc/machine-role.d")
	if entries, err := os.ReadDir(markers); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if stdstrings.HasSuffix(name, ".conf") && !contains(view.Roles, stdstrings.TrimSuffix(name, ".conf")) {
				_ = os.Remove(filepath.Join(markers, name))
			}
		}
	}
	rolesChanged := false
	for _, role := range view.Roles {
		updated, err := writeIfChanged(filepath.Join(markers, role+".conf"), "ROLE="+role+"\n", 0o644)
		if err != nil {
			return changed, err
		}
		rolesChanged = rolesChanged || updated
	}
	if rolesChanged {
		changed = append(changed, "roles")
		host.Run("hostnamectl", append([]string{"tags"}, view.Roles...)...)
		host.Run("systemctl", "start", "systemd-sysupdate-auto-enable.service")
	}
	for _, spec := range files {
		path := hostPath(root, runDirectory, spec.Path)
		content := ""
		if spec.applies(view) {
			rendered, err := view.render(spec)
			if err != nil {
				return changed, err
			}
			content = rendered
		}
		if stdstrings.TrimSpace(content) == "" {
			if removeFile(path) && spec.Stop != "" {
				host.Run("systemctl", "stop", spec.Stop)
			}
			continue
		}
		updated, err := writeIfChanged(path, content, spec.Mode)
		if err != nil {
			return changed, err
		}
		if !updated {
			continue
		}
		changed = append(changed, spec.Path)
		if spec.Reload != "" {
			host.Run("systemctl", "reload-or-restart", spec.Reload)
		}
		if spec.Start != "" {
			host.Run("systemctl", "start", "--no-block", spec.Start)
		}
	}
	return changed, nil
}
