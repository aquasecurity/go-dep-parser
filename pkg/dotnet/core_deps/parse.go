package core_deps

import (
	"fmt"
	"io"
	"strings"

	"github.com/liamg/jfather"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"

	"github.com/aquasecurity/go-dep-parser/pkg/log"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func splitNameVer(nameVer string) (name, version string) {
	split := strings.Split(nameVer, "/")
	if len(split) != 2 {
		// Invalid name
		log.Logger.Warnf("Cannot parse .NET library version from: %s", nameVer)
		return "", ""
	}
	name = split[0]
	version = split[1]
	return
}

func joinNameVer(name, version string) (nameVer string) {
	return fmt.Sprintf("%s/%s", name, version)
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var depsFile dotNetDependencies

	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("read error: %w", err)
	}
	if err := jfather.Unmarshal(input, &depsFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode .deps.json file: %w", err)
	}

	var libraries []types.Library
	var deps []types.Dependency
	for pkgNameVersion, target := range depsFile.Targets[depsFile.RuntimeTarget.Name] {
		library, ok := depsFile.Libraries[pkgNameVersion]
		if !ok {
			continue
		}

		name, version := splitNameVer(pkgNameVersion)
		if name == "" || version == "" {
			continue
		}

		lib := types.Library{
			ID:        utils.PackageID(name, version),
			Name:      name,
			Version:   version,
			Locations: []types.Location{{StartLine: library.StartLine, EndLine: library.EndLine}},
		}

		var childDeps []string
		for depName, depVersion := range target.Dependencies {
			nameVer := joinNameVer(depName, depVersion)
			_, ok := depsFile.Libraries[nameVer]
			if !ok {
				continue
			}
			depID := utils.PackageID(depName, depVersion)
			childDeps = append(childDeps, depID)
		}

		deps = append(deps, types.Dependency{
			ID:        lib.ID,
			DependsOn: childDeps,
		})

		libraries = append(libraries, lib)
	}

	return libraries, deps, nil
}

type dotNetDependencies struct {
	RuntimeTarget dotNetRuntimeTarget                `json:"runtimeTarget"`
	Libraries     map[string]dotNetLibrary           `json:"libraries"`
	Targets       map[string]map[string]dotNetTarget `json:"targets"`
}

type dotNetRuntimeTarget struct {
	Name string `json:"name"`
}

type dotNetTarget struct {
	Dependencies map[string]string   `json:"dependencies"`
	Runtime      map[string]struct{} `json:"runtime"`
}

type dotNetLibrary struct {
	Type      string `json:"type"`
	StartLine int
	EndLine   int
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (t *dotNetLibrary) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}
