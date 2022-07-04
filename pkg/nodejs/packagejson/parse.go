package packagejson

import (
	"encoding/json"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type PackageRef struct {
	Type string
	Url  string
}
type PackageJSON struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	License    interface{} `json:"license"`
	Homepage   string      `json:"homepage,omitempty"`
	Repository PackageRef  `json:"repository,omitempty"`
	Bugs       PackageRef  `json:"bugs,omitempty"`
	Funding    PackageRef  `json:"funding,omitempty"`
}
type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) GetExternalRefs(packageJson PackageJSON) []types.ExternalRef {
	externalRefs := []types.ExternalRef{}
	if packageJson.Homepage != "" {
		externalRefs = append(externalRefs, types.ExternalRef{Type: types.Website, URL: packageJson.Homepage})
	}
	switch v := packageJson.License.(type) {
	case map[string]interface{}:
		if licenseUrl, ok := v["url"]; ok {
			externalRefs = append(externalRefs, types.ExternalRef{Type: types.License, URL: licenseUrl.(string)})
		}
	}

	if (packageJson.Repository != PackageRef{}) {
		externalRefs = append(externalRefs, types.ExternalRef{Type: types.VCS, URL: packageJson.Repository.Url})
	}

	if (packageJson.Bugs != PackageRef{}) {
		externalRefs = append(externalRefs, types.ExternalRef{Type: types.IssueTracker, URL: packageJson.Bugs.Url})
	}

	return externalRefs
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var data PackageJSON
	err := json.NewDecoder(r).Decode(&data)
	if err != nil {
		return nil, nil, xerrors.Errorf("JSON decode error: %w", err)
	}

	if data.Name == "" || data.Version == "" {
		return nil, nil, xerrors.Errorf("unable to parse package.json")
	}

	return []types.Library{{
		Name:               data.Name,
		Version:            data.Version,
		License:            parseLicense(data.License),
		ExternalReferences: p.GetExternalRefs(data),
	}}, nil, nil
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
