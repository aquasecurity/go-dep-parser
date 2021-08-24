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
	License interface{} `json:"license"`
}

type LegacyLicense struct {
	Type string `json:"type"`
	Url  string `json:"url"`
}

func Parse(r io.Reader) (types.Library, error) {
	var data packageJSON
	err := json.NewDecoder(r).Decode(&data)
	if err != nil {
		return types.Library{}, xerrors.Errorf("decode error: %w", err)
	}

	var lib types.Library
	// the license isn't always a string, check for legacy struct if not string
	license := ParseLicense(data.License)
	if data.Name != "" && data.Version != "" {
		lib = types.Library{
			Name:    data.Name,
			Version: data.Version,
			License: license,
		}
	}
	return lib, nil
}

func ParseLicense(val interface{}) string {
	license, ok := val.(string)
	if !ok {
		legacyLicenseInst, ok := val.(LegacyLicense)
		if ok {
			license = legacyLicenseInst.Type
		}
	}
	return license
}
