package packagejson

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type packageJSON struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	SHA     string      `json:"_shasum"`
	License interface{} `json:"license"`
}

func Parse(r io.Reader) (types.Library, error) {
	var pkg packageJSON
	err := json.NewDecoder(r).Decode(&pkg)
	if err != nil {
		return types.Library{}, xerrors.Errorf("decode error: %w", err)
	}

	// the license isn't always a string, so only take it if it is a string
	license, _ := pkg.License.(string)

	if pkg.Name == "" || pkg.Version == "" {
		return types.Library{}, xerrors.Errorf("unable to parse package.json")
	}

	return types.Library{
		Name:    pkg.Name,
		Version: pkg.Version,
		License: license,
	}, nil
}
