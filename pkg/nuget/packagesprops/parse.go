package config

import (
	"encoding/xml"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type propsPackageEntry struct {
	Version            string `xml:"Version,attr"`
	UpdatePackageName  string `xml:"Update,attr"`
	IncludePackageName string `xml:"Include,attr"`
}

type propsPackageReferenceEntry struct {
	xml.Name `xml:"PackageReference"`
	propsPackageEntry
}

type propsPackageVersionEntry struct {
	xml.Name `xml:"PackageVersion"`
	propsPackageEntry
}

type propsItemGroup struct {
	xml.Name          `xml:"ItemGroup"`
	ReferencePackages []propsPackageReferenceEntry `xml:"PackageReference"`
	VersionPackages   []propsPackageVersionEntry   `xml:"PackageVersion"`
}

type propsProject struct {
	ItemGroups []propsItemGroup `xml:"ItemGroup"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func parsePackage(pkg propsPackageEntry) types.Library {
	// Update attribute is considered legacy, so preferring Include
	name := pkg.UpdatePackageName
	if pkg.IncludePackageName != "" {
		name = pkg.IncludePackageName
	}
	return types.Library{
		ID:      utils.PackageID(name, pkg.Version),
		Name:    name,
		Version: pkg.Version,
	}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var configData propsProject
	if err := xml.NewDecoder(r).Decode(&configData); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode '*.packages.props' file: %w", err)
	}
	// https://github.com/dotnet/roslyn-tools/blob/8617f451b13e3dc29751cc78109f32ec73eeedb0/src/RoslynInsertionTool/RoslynInsertionTool/CoreXT.cs#L488
	// Based on this documentation both legacy packages.props and Directory.packages.props are supported

	libs := make([]types.Library, 0)
	for _, itemGroup := range configData.ItemGroups {
		for _, refPkg := range itemGroup.ReferencePackages {
			var pkg = propsPackageEntry{refPkg.Version, refPkg.UpdatePackageName, refPkg.IncludePackageName}
			var lib = parsePackage(pkg)
			if len(lib.Name) > 0 && len(lib.Version) > 0 {
				libs = append(libs, lib)
			}
		}

		for _, verPkg := range itemGroup.VersionPackages {
			var pkg = propsPackageEntry{verPkg.Version, verPkg.UpdatePackageName, verPkg.IncludePackageName}
			var lib = parsePackage(pkg)
			if len(lib.Name) > 0 && len(lib.Version) > 0 {
				libs = append(libs, lib)
			}
		}
	}
	return utils.UniqueLibraries(libs), nil, nil
}
