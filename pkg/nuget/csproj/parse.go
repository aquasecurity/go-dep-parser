package csproj

import (
	"encoding/xml"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type cfgPackageReference struct {
	XMLName           xml.Name `xml:"PackageReference"`
	Version           string   `xml:"Version,attr"`
	Include           string   `xml:"Include,attr"`
	PrivateAssetsTag  string   `xml:"PrivateAssets"`
	PrivateAssetsAttr string   `xml:"PrivateAssets,attr"`
	ExcludeAssetsTag  string   `xml:"ExcludeAssets"`
	ExcludeAssetsAttr string   `xml:"ExcludeAssets,attr"`
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
		if pkg.Include == "" || isDevDependency(pkg) {
			continue
		}

		var versionNotFloating = strings.TrimRight(pkg.Version, ".*")

		lib := types.Library{
			Name:    pkg.Include,
			Version: versionNotFloating,
		}

		libs = append(libs, lib)
	}

	return utils.UniqueLibraries(libs), nil, nil
}

func isDevDependency(pkg cfgPackageReference) bool {
	var privateAssets = tagOrAttribute(pkg.PrivateAssetsTag, pkg.PrivateAssetsAttr)
	var excludeAssets = tagOrAttribute(pkg.ExcludeAssetsTag, pkg.ExcludeAssetsAttr)
	return assetListContains(privateAssets, "all") || assetListContains(excludeAssets, "all") || assetListContains(excludeAssets, "runtime")
}

func assetListContains(assets []string, needle string) bool {
	for _, v := range assets {
		if strings.EqualFold(v, needle) {
			return true
		}
	}
	return false
}

func tagOrAttribute(tag string, attr string) []string {
	var strvalue = "";
	if (tag != "") {
		strvalue = tag
	} else {
		strvalue = attr
	}
	return strings.Split(strvalue, ";")
}
