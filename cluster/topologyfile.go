package cluster

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
	return DecodeObj(data)
}

func yamlToJSON(data []byte) ([]byte, error) {
	var value any
	if err := yaml.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}
