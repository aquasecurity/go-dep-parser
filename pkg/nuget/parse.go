package nuget

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"io"
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
	Dependencies map[string]map[string]Dependency
}

type Dependency struct {
	Type         string
	Resolved     string
	Dependencies map[string]string
	ContentHash  string
}

func Parse(r io.Reader) ([]types.Library, error) {
	var lockFile LockFile
	decoder := json.NewDecoder(r)
	err := decoder.Decode(&lockFile)
	if err != nil {
		return nil, err
	}

	var libraries []types.Library
	unique := map[string]struct{}{}

	for _, targetContent := range lockFile.Dependencies {
		for topPkgName, topPkgContent := range targetContent {
			for pkgName, version := range topPkgContent.Dependencies {
				symbol := fmt.Sprintf("%s@%s", pkgName, version)
				if _, ok := unique[symbol]; ok {
					continue
				}

				libraries = append(libraries, types.Library{
					Name:    pkgName,
					Version: version,
				})
				unique[symbol] = struct{}{}
			}

			if topPkgContent.Type == "Project" {
				continue
			}

			symbol := fmt.Sprintf("%s@%s", topPkgName, topPkgContent)
			if _, ok := unique[symbol]; ok {
				continue
			}

			libraries = append(libraries, types.Library{
				Name:    topPkgName,
				Version: topPkgContent.Resolved,
			})
		}
	}

	return libraries, nil
}
