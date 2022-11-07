package lock

import (
	"encoding/json"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type LockFile struct {
	Version int
	Targets map[string]Dependencies `json:"dependencies"`
}

type Dependencies map[string]Dependency

type Dependency struct {
	Type         string
	Resolved     string
	Dependencies map[string]string `json:"dependencies,omitempty"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockFile LockFile
	decoder := json.NewDecoder(r)

	if err := decoder.Decode(&lockFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode packages.lock.json: %w", err)
	}

	libs := make([]types.Library, 0)
	depsMap := make(map[string][]string)
	for _, targetContent := range lockFile.Targets {
		for packageName, packageContent := range targetContent {
			// If package type is "project", it is the actual project, and we skip it.
			if packageContent.Type == "Project" {
				continue
			}

			lib := types.Library{
				Name:    packageName,
				Version: packageContent.Resolved,
			}
			libs = append(libs, lib)

			depId := utils.PackageID(packageName, packageContent.Resolved)
			dependsOn := make([]string, 0)

			for depName := range packageContent.Dependencies {
				dependsOn = append(dependsOn, utils.PackageID(depName, targetContent[depName].Resolved))
			}

			if depsMap[depId] != nil {
				dependsOn = append(dependsOn, depsMap[depId]...)
				if dependsOn = utils.UniqueStrings(dependsOn); dependsOn == nil {
					dependsOn = make([]string, 0)
				}
			}

			depsMap[depId] = dependsOn
		}
	}

	deps := make([]types.Dependency, 0)
	for depId, dependsOn := range depsMap {
		dep := types.Dependency{
			ID:        depId,
			DependsOn: dependsOn,
		}
		deps = append(deps, dep)
	}

	return utils.UniqueLibraries(libs), deps, nil
}
