package packagejson

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
	"golang.org/x/xerrors"
)

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	License              interface{}       `json:"license"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	Workspaces           []string          `json:"workspaces"`
}

type Package struct {
	types.Library
	Dependencies         map[string]string
	OptionalDependencies map[string]string
	DevDependencies      map[string]string
	Workspaces           []string
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r io.Reader) (Package, error) {
	var pkgJSON packageJSON
	if err := json.NewDecoder(r).Decode(&pkgJSON); err != nil {
		return Package{}, xerrors.Errorf("JSON decode error: %w", err)
	}

	var id string
	// Name and version fields are optional
	// https://docs.npmjs.com/cli/v9/configuring-npm/package-json#name
	if pkgJSON.Name != "" && pkgJSON.Version != "" {
		id = utils.PackageID(pkgJSON.Name, pkgJSON.Version)
	}

	return Package{
		Library: types.Library{
			ID:      id,
			Name:    pkgJSON.Name,
			Version: pkgJSON.Version,
			License: parseLicense(pkgJSON.License),
		},
		Dependencies:         pkgJSON.Dependencies,
		OptionalDependencies: pkgJSON.OptionalDependencies,
		DevDependencies:      pkgJSON.DevDependencies,
		Workspaces:           pkgJSON.Workspaces,
	}, nil
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
