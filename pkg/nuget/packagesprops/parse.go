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

type itemGroup struct {
	PackageReferenceEntry []entry `xml:"PackageReference"`
	PackageVersionEntry   []entry `xml:"PackageVersion"`
}

type project struct {
	ItemGroups []itemGroup `xml:"ItemGroup"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func parsePackage(pkg entry) types.Library {
	// Update attribute is considered legacy, so preferring Include
	name := strings.Trim(pkg.UpdatePackageName, " ")
	if pkg.IncludePackageName != "" {
		name = strings.Trim(pkg.IncludePackageName, " ")
	}
	version := strings.Trim(pkg.Version, " ")
	return types.Library{
		ID:      utils.PackageID(name, version),
		Name:    name,
		Version: version,
	}
}

func shouldSkipLib(lib types.Library) bool {
	if len(lib.Name) == 0 || len(lib.Version) == 0 {
		return false
	}
	// *packages.props files don't contain variable resolution information.
	// So we need to skip them.
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
	var configData project
	if err := xml.NewDecoder(r).Decode(&configData); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode '*.packages.props' file: %w", err)
	}
	// https://github.com/dotnet/roslyn-tools/blob/b4c5220f5dfc4278847b6d38eff91cc1188f8066/src/RoslynInsertionTool/RoslynInsertionTool/CoreXT.cs#L150
	// Based on this documentation both legacy packages.props and Directory.packages.props are supported
	// Directory.packages.props example: https://github.com/NuGet/Home/wiki/Centrally-managing-NuGet-package-versions

	libs := make([]types.Library, 0)
	for _, itemGroup := range configData.ItemGroups {
		for _, refPkg := range append(itemGroup.PackageReferenceEntry, itemGroup.PackageVersionEntry...) {
			pkg := entry{refPkg.Version, refPkg.UpdatePackageName, refPkg.IncludePackageName}
			lib := parsePackage(pkg)
			if shouldSkipLib(lib) {
				libs = append(libs, lib)
			}
		}
	}
	return utils.UniqueLibraries(libs), nil, nil
}
