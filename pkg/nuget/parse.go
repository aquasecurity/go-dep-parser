package nuget

import (
	"encoding/json"
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

// The lockfile that nuget uses (packages.lock.json) works basically like this:
// Each 'build type' (for example .NETCoreApp,Version=v3.1) have a set of dependencies.
// Those dependencies can be 'Direct', 'Transitive' and 'Project'.
// The dependency consists of a string value key (package name) and an object,
// from which we need to fetch a few different values.
// The following values should be parsed right away: resolved (resolved version),
// type (this information might be worth having) and finally, it's dependencies.
// The dependencies in this stage of the file are only a string map where the key is package name
// and value is package version.

type LockFile struct {
	Version      int
	Targets map[string]Dependencies `json:"dependencies"`
}

type Dependencies map[string]Dependency

type Dependency struct {
	Type         string
	Resolved     string
	Dependencies map[string]string
	ContentHash  string
}

func Parse(r io.Reader) ([]types.Library, error) {
	var lockFile LockFile
	decoder := json.NewDecoder(r)

	if err := decoder.Decode(&lockFile); err != nil {
		return nil, xerrors.Errorf("failed to decode packages.lock.json: %w", err)
	}

	var libraries []types.Library
	unique := map[string]struct{}{}

	for _, targetContent := range lockFile.Targets {
		// Add all direct dependencies first (as they will be resolved as the used package).
		for topPkgName, topPkgContent := range targetContent {
			if topPkgContent.Type == "Project" {
				continue
			}

			if _, ok := unique[topPkgName]; ok {
				continue
			}

			libraries = append(libraries, types.Library{
				Name:    topPkgName,
				Version: topPkgContent.Resolved,
			})

			unique[topPkgName] = struct{}{}
		}
		// Then add sub-dependencies that are not already resolved.
		for _, topPkgContent := range targetContent {
			for pkgName, version := range topPkgContent.Dependencies {
				if _, ok := unique[pkgName]; ok {
					continue
				}

				libraries = append(libraries, types.Library{
					Name:    pkgName,
					Version: version,
				})
				unique[pkgName] = struct{}{}
			}
		}
	}

	return libraries, nil
}
