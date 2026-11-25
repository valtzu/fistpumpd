package cluster

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func ReadTopologyFile(path string) (Obj, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	switch filepath.Ext(path) {
	case ".yaml", ".yml":
		data, err = yamlToJSON(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	document, err := DecodeObj(data)
	if err != nil {
		return nil, err
	}
	if err := inlineTemplateFiles(document, filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return document, nil
}

func inlineTemplateFiles(document Obj, directory string) error {
	files, _ := document["files"].([]any)
	for index, item := range files {
		spec, ok := item.(Obj)
		if !ok {
			continue
		}
		name, given := spec["template_file"]
		if !given {
			continue
		}
		if _, both := spec["template"]; both {
			return fmt.Errorf("file %d has both template and template_file", index)
		}
		relative, ok := name.(string)
		if !ok || !filepath.IsLocal(relative) {
			return fmt.Errorf("file %d: template_file must be a path inside the topology's directory", index)
		}
		text, err := os.ReadFile(filepath.Join(directory, relative))
		if err != nil {
			return err
		}
		delete(spec, "template_file")
		spec["template"] = strings.TrimRight(string(text), "\n")
	}
	return nil
}

func yamlToJSON(data []byte) ([]byte, error) {
	var value any
	if err := yaml.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
