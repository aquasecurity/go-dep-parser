package meta

import (
	"encoding/json"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var data packageJSON
	err := json.NewDecoder(r).Decode(&data)
	if err != nil {
		return nil, nil, xerrors.Errorf("JSON decode error: %w", err)
	}

	if data.Name == "" || data.Version == "" {
		return nil, nil, xerrors.Errorf("unable to parse package.json")
	}

	return []types.Library{{
		Name:    data.Name,
		Version: data.Version,
		License: data.License,
	}}, nil, nil
}
