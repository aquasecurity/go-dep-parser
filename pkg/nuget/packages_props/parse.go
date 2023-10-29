package config

import (
	"encoding/xml"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

	


type propsPackageEntry struct{
	Version         string   `xml:"Version,attr"`
	UpdatePackageName     string   `xml:"Update,attr"`
	IncludePackageName     string   `xml:"Include,attr"`
}

type propsPackageReferenceEntry struct {
	XMLName         xml.Name `xml:"PackageReference"`
	propsPackageEntry
}

type propsPackageVersionEntry struct {
	XMLName         xml.Name `xml:"PackageVersion"`
	propsPackageEntry
}

type propsItemGroup struct {
	XMLName  xml.Name              `xml:"ItemGroup"`
	ReferencePackages []propsPackageReferenceEntry `xml:"PackageReference"`
	VersionPackages []propsPackageVersionEntry `xml:"PackageVersion"`
}

type propsProject struct {
	XMLName xml.Name `xml:"Project"`
	ItemGroups []propsItemGroup `xml:"ItemGroup"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) addPackage(libs* []types.Library, pkg propsPackageEntry) {
	if ((len(pkg.UpdatePackageName) == 0 && len(pkg.IncludePackageName) == 0 ) || len(pkg.Version) == 0){
		return
	}
	var lib types.Library
	// Update attribute is considered legacy, so preferring Include
	if (len(pkg.IncludePackageName) > 0 ){
		lib = types.Library{
			Name:    pkg.IncludePackageName,
			Version: pkg.Version,
		}
	}else{
		lib = types.Library{
			Name:    pkg.UpdatePackageName,
			Version: pkg.Version,
		}
	}
	*libs = append(*libs, lib)
}


func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var configData propsProject
	if err := xml.NewDecoder(r).Decode(&configData); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode  .props file: %w", err)
	}
	// https://github.com/dotnet/roslyn-tools/blob/8617f451b13e3dc29751cc78109f32ec73eeedb0/src/RoslynInsertionTool/RoslynInsertionTool/CoreXT.cs#L488
	// Based on this documentation both legacy packages.props and Directory.packages.props are supported

	libs := make([]types.Library, 0)
	for _, itemGroup := range configData.ItemGroups{
		for _, refPkg := range itemGroup.ReferencePackages{
			var pkg = propsPackageEntry{refPkg.Version, refPkg.UpdatePackageName, refPkg.IncludePackageName}
			p.addPackage(&libs, pkg)
		}

		for _, verPkg := range itemGroup.VersionPackages{
			var pkg = propsPackageEntry{verPkg.Version, verPkg.UpdatePackageName, verPkg.IncludePackageName}
			p.addPackage(&libs, pkg)
		}
	}
	return utils.UniqueLibraries(libs), nil, nil
}


