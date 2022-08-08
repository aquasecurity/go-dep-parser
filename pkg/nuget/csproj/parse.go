package csproj

import (
	"encoding/xml"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type cfgPackageReference struct {
	XMLName       xml.Name `xml:"PackageReference"`
	Version       string   `xml:"Version,attr"`
	Include       string   `xml:"Include,attr"`
	PrivateAssets string   `xml:"PrivateAssets"`
}

type config struct {
	XMLName  xml.Name              `xml:"Project"`
	Packages []cfgPackageReference `xml:"ItemGroup>PackageReference"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var cfgData config
	if err := xml.NewDecoder(r).Decode(&cfgData); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode .csproj file: %w", err)
	}

	libs := make([]types.Library, 0)
	for _, pkg := range cfgData.Packages {
		if pkg.Include == "" || pkg.PrivateAssets != "" {
			continue
		}

		lib := types.Library{
			Name:    pkg.Include,
			Version: pkg.Version,
		}

		libs = append(libs, lib)
	}

	return utils.UniqueLibraries(libs), nil, nil
}
