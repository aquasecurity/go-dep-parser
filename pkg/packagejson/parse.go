package packagejson

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type packageDotJSON struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	SHA     string      `json:"_shasum"`
	License interface{} `json:"license"`
}

func Parse(r io.Reader) ([]types.Library, error) {
	libs := []types.Library{}
	var data packageDotJSON
	err := json.NewDecoder(r).Decode(&data)
	if err != nil {
		return libs, xerrors.Errorf("decode error: %w", err)
	}

	// the license isn't always a string, so only take it if it is a string
	license, _ := data.License.(string)

	if data.Name != "" && data.Version != "" {
		libs = append(libs, types.Library{
			Name:    data.Name,
			Version: data.Version,
			License: license,
		})
	}
	return libs, nil
}
