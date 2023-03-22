package composer

import (
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
	"github.com/liamg/jfather"
	"golang.org/x/exp/maps"
	"io"
	"sort"
	"strings"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type lockFile struct {
	Packages []packageInfo `json:"packages"`
}
type packageInfo struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Require   map[string]string `json:"require"`
	License   []string          `json:"license"`
	StartLine int
	EndLine   int
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockFile lockFile
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("read error: %w", err)
	}
	if err = jfather.Unmarshal(input, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	libs := map[string]types.Library{}
	var foundDeps []types.Dependency
	for _, pkg := range lockFile.Packages {
		lib := types.Library{
			ID:        utils.PackageID(pkg.Name, pkg.Version),
			Name:      pkg.Name,
			Version:   pkg.Version,
			Indirect:  false, // composer.lock file doesn't have info about Direct/Indirect deps. Will think that all dependencies are Direct
			License:   strings.Join(pkg.License, ", "),
			Locations: []types.Location{{StartLine: pkg.StartLine, EndLine: pkg.EndLine}},
		}
		libs[lib.Name] = lib

		var dependsOn []string
		for depName := range pkg.Require {
			if depName != "php" { // Require field includes required php version, skip this
				dependsOn = append(dependsOn, depName) // field uses range of versions, so later we will fill in the versions from the libraries
			}
		}
		if len(dependsOn) > 0 {
			dep := types.Dependency{
				ID:        lib.ID,
				DependsOn: dependsOn,
			}
			foundDeps = append(foundDeps, dep)
		}
	}

	// fill deps versions
	var deps []types.Dependency
	for _, dep := range foundDeps {
		var dependsOn []string
		for _, depName := range dep.DependsOn {
			if lib, ok := libs[depName]; ok {
				dependsOn = append(dependsOn, lib.ID)
				continue
			}
			log.Logger.Debugf("unable to find version of %s", depName)
		}
		if len(dependsOn) > 0 {
			dependsOn = sortDependsOn(dependsOn)
			deps = append(deps, types.Dependency{
				ID:        dep.ID,
				DependsOn: dependsOn,
			})
		}
	}

	return maps.Values(libs), deps, nil
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (t *packageInfo) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}

func sortDependsOn(dependsOn []string) []string {
	sort.Slice(dependsOn, func(i, j int) bool {
		return dependsOn[i] < dependsOn[j]
	})
	return dependsOn
}
