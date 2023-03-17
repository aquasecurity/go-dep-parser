package packagejson

import (
	"encoding/json"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type packageJSON struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	License      interface{}       `json:"license"`
	Dependencies map[string]string `json:"dependencies"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var data packageJSON
	var libs []types.Library
	err := json.NewDecoder(r).Decode(&data)
	if err != nil {
		return nil, nil, xerrors.Errorf("JSON decode error: %w", err)
	}

	// root library
	if data.Name == "" || data.Version == "" {
		return nil, nil, xerrors.Errorf("unable to parse package.json")
	}
	rootLib := types.Library{
		ID:      utils.PackageID(data.Name, data.Version),
		Name:    data.Name,
		Version: data.Version,
		License: parseLicense(data.License),
		Root:    true,
	}
	libs = append(libs, rootLib)

	// dependencies
	for depName, depVersion := range data.Dependencies {
		lib := types.Library{
			Name:    depName,
			Version: depVersion,
		}
		libs = append(libs, lib)
	}

	return libs, nil, nil
}

func parseLicense(val interface{}) string {
	// the license isn't always a string, check for legacy struct if not string
	switch v := val.(type) {
	case string:
		return v
	case map[string]interface{}:
		if license, ok := v["type"]; ok {
			return license.(string)
		}
	}
	return ""
}
