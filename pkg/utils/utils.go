package utils

import (
	"fmt"
	"sort"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/exp/maps"
)

func UniqueStrings(ss []string) []string {
	var results []string
	uniq := map[string]struct{}{}
	for _, s := range ss {
		if _, ok := uniq[s]; ok {
			continue
		}
		results = append(results, s)
		uniq[s] = struct{}{}
	}
	return results
}

func UniqueLibraries(libs []types.Library) []types.Library {
	if len(libs) == 0 {
		return nil
	}
	unique := map[string]types.Library{}
	for _, lib := range libs {
		identifier := fmt.Sprintf("%s@%s", lib.Name, lib.Version)
		if l, ok := unique[identifier]; !ok {
			unique[identifier] = lib
		} else if len(lib.Locations) > 0 {
			// merge locations
			l.Locations = append(l.Locations, lib.Locations...)
			sort.Slice(l.Locations, func(i, j int) bool {
				return l.Locations[i].StartLine < l.Locations[j].StartLine
			})
			unique[identifier] = l
		}
	}
	return maps.Values(unique)
}

func MergeMaps(parent, child map[string]string) map[string]string {
	if parent == nil {
		return child
	}
	for k, v := range child {
		parent[k] = v
	}
	return parent
}

func PackageID(name, version string) string {
	return fmt.Sprintf("%s@%s", name, version)
}

func SortLibs(libs []types.Library) []types.Library {
	sort.Slice(libs, func(i, j int) bool {
		return libs[i].ID < libs[j].ID
	})
	return libs
}

func SortDeps(deps []types.Dependency) []types.Dependency {
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].ID < deps[j].ID
	})
	return deps
}

func SortDependsOn(dependsOn []string) []string {
	sort.Slice(dependsOn, func(i, j int) bool {
		return dependsOn[i] < dependsOn[j]
	})
	return dependsOn
}
