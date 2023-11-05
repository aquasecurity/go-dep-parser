package packagesprops

import (
	"encoding/xml"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type entry struct {
	Version            string `xml:"Version,attr"`
	UpdatePackageName  string `xml:"Update,attr"`
	IncludePackageName string `xml:"Include,attr"`
}

type propsItemGroup struct {
	xml.Name              `xml:"ItemGroup"`
	PackageReferenceEntry []entry `xml:"PackageReference"`
	PackageVersionEntry   []entry `xml:"PackageVersion"`
}

type propsProject struct {
	ItemGroups []propsItemGroup `xml:"ItemGroup"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func parsePackage(pkg entry) types.Library {
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

func isNonEmptyNonVariableLib(lib types.Library) bool {
	if len(lib.Name) == 0 || len(lib.Version) == 0 {
		return false
	}
	if isVariable(lib.Name) || isVariable(lib.Version) {
		return false
	}
	return true

}

func isVariable(s string) bool {
	trimmed := strings.Trim(s, " ")
	return strings.HasPrefix(trimmed, "$(") && strings.HasSuffix(trimmed, ")")
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var configData propsProject
	if err := xml.NewDecoder(r).Decode(&configData); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode '*.packages.props' file: %w", err)
	}
	// https://github.com/dotnet/roslyn-tools/blob/b4c5220f5dfc4278847b6d38eff91cc1188f8066/src/RoslynInsertionTool/RoslynInsertionTool/CoreXT.cs#L150
	// Based on this documentation both legacy packages.props and Directory.packages.props are supported
	// Directory.packages.props example: https://github.com/NuGet/Home/wiki/Centrally-managing-NuGet-package-versions

	libs := make([]types.Library, 0)
	for _, itemGroup := range configData.ItemGroups {
		for _, refPkg := range append(itemGroup.PackageReferenceEntry, itemGroup.PackageVersionEntry...) {
			var pkg = entry{refPkg.Version, refPkg.UpdatePackageName, refPkg.IncludePackageName}
			var lib = parsePackage(pkg)
			if isNonEmptyNonVariableLib(lib) {
				libs = append(libs, lib)
			}
		}
	}
	return utils.UniqueLibraries(libs), nil, nil
}
