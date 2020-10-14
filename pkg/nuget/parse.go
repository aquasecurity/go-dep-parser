package nuget

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"io"
)

// The lockfile that nuget uses (packages.lock.json) works basically like this:
// Each 'build type' (for example .NETCoreApp,Version=v3.1) have a set of dependencies.
// Those dependencies can be 'Direct', 'Transitive' and 'Project'
// (meaning of those are quite self explanatory I think). The dependency consists of a string
// value key (package name) and an object, from which we need to fetch a few different values.
// The following values should be parsed right away: resolved (resolved version),
// type (this information might be worth having) and finally, it's dependencies.
// The dependencies in this stage of the file are only a string map where the key is package name
// and value is package version.

type LockFile struct {
	Version      int
	Dependencies map[string]map[string]Dependency
}

type Dependency struct {
	Type         string            `json:"type"`
	Resolved     string            `json:"resolved"`
	Dependencies map[string]string `json:"dependencies"`
	ContentHash  string            `json:"contentHash"`
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

	// The first loop is the targets (.NETCoreApp,Version=v3.1)
	// that means that it's not really a package, but there are dependencies
	// under said target.
	for _, targetContent := range lockFile.Dependencies {
		// Here comes the 'real' dependencies.
		for topPkgName, topPkgContent := range targetContent {
			// And inside the dependency, there are another level of dependencies.
			// But that's actually it, I swear!
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

			// To make sure that we don't add the package itself, we run
			// a check here.
			if topPkgContent.Type == "Project" {
				continue
			}

			// Else, if not unique, add the package to library list.
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
