package npm

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type LockFile struct {
	Dependencies map[string]Dependency
}
type Dependency struct {
	Version      string
	Dev          bool
	Dependencies map[string]Dependency
	Requires     map[string]string
}

func Parse(r io.Reader) ([]types.Library, []types.Dependency, error) {
	var lockFile LockFile
	decoder := json.NewDecoder(r)
	err := decoder.Decode(&lockFile)
	if err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	libs, deps := parse(lockFile.Dependencies)

	return unique(libs), deps, nil
}

func parse(dependencies map[string]Dependency) ([]types.Library, []types.Dependency) {
	var libs []types.Library
	var deps []types.Dependency
	for pkgName, dependency := range dependencies {
		if dependency.Dev {
			continue
		}

		lib := types.Library{Name: pkgName, Version: dependency.Version}
		libs = append(libs, lib)
		dependsOn := make([]string, 0, len(dependency.Requires))
		for k := range dependency.Requires {
			dependsOn = append(dependsOn, k)
		}
		deps = append(deps, types.Dependency{ID: types.ID(lib), DependsOn: dependsOn})

		if dependency.Dependencies != nil {
			// Recursion
			childLibs, childDeps := parse(dependency.Dependencies)
			libs = append(libs, childLibs...)
			resolve(childLibs, childDeps)
			deps = append(deps, childDeps...)
		}
	}

	resolve(libs, deps)

	return libs, deps
}
func resolve(libs []types.Library, deps []types.Dependency) {
	resolved := make(map[string]types.Library)
	for _, lib := range libs {
		resolved[lib.Name] = lib
	}
	for _, dep := range deps {
		for i := range dep.DependsOn {
			pkg := dep.DependsOn[i]
			resolvedLib, ok := resolved[pkg]
			if ok {
				dep.DependsOn[i] = types.ID(resolvedLib)
			}
		}
	}
}

func unique(libs []types.Library) []types.Library {
	var uniqLibs []types.Library
	unique := map[types.Library]struct{}{}
	for _, lib := range libs {
		if _, ok := unique[lib]; !ok {
			unique[lib] = struct{}{}
			uniqLibs = append(uniqLibs, lib)
		}
	}
	return uniqLibs
}
