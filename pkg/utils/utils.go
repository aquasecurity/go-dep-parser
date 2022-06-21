package utils

import (
	"bytes"
	"encoding/gob"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
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
	var uniqLibs []types.Library
	unique := map[string]struct{}{}
	for _, lib := range libs {
		h := hash(lib)
		if _, ok := unique[h]; !ok {
			unique[h] = struct{}{}
			uniqLibs = append(uniqLibs, lib)
		}
	}
	return uniqLibs
}

func hash(lib types.Library) string {
	var b bytes.Buffer
	gob.NewEncoder(&b).Encode(lib)
	return b.String()
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
