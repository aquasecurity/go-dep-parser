package core_deps

import (
	"fmt"
	"io"
	"strings"

	"github.com/liamg/jfather"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"

	"github.com/aquasecurity/go-dep-parser/pkg/log"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func packageID(name, version string) string {
	return fmt.Sprintf("%s/%s", name, version)
}

func splitNameVer(nameVer string) (string, string) {
	split := strings.Split(nameVer, "/")
	if len(split) != 2 {
		// Invalid name
		log.Logger.Warnf("Cannot parse .NET library version from: %s", nameVer)
		return "", ""
	}
	return split[0], split[1]
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
	targets := depsFile.Targets[depsFile.RuntimeTarget.Name]
	for pkgNameVersion, target := range targets {
		name, version := splitNameVer(pkgNameVersion)
		if name == "" || version == "" {
			continue
		}

		lib := types.Library{
			ID:        packageID(name, version),
			Name:      name,
			Version:   version,
			Locations: []types.Location{{StartLine: target.StartLine, EndLine: target.EndLine}},
		}

		var childDeps []string
		for depName, depVersion := range target.Dependencies {
			depID := packageID(depName, depVersion)
			if _, ok := targets[depID]; ok {
				childDeps = append(childDeps, depID)
			}
		}

		if len(childDeps) > 0 {
			deps = append(deps, types.Dependency{
				ID:        lib.ID,
				DependsOn: childDeps,
			})
		}

		libraries = append(libraries, lib)
	}

	return libraries, deps, nil
}

type dotNetDependencies struct {
	RuntimeTarget dotNetRuntimeTarget                `json:"runtimeTarget"`
	Targets       map[string]map[string]dotNetTarget `json:"targets"`
}

type dotNetRuntimeTarget struct {
	Name string `json:"name"`
}

type dotNetTarget struct {
	Dependencies map[string]string   `json:"dependencies"`
	Runtime      map[string]struct{} `json:"runtime"`
	StartLine    int
	EndLine      int
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (t *dotNetTarget) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}
