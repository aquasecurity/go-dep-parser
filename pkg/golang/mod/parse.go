package mod

import (
	"io"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/mod/modfile"
	"golang.org/x/xerrors"
)

// Parse parses a go.mod file
func Parse(r io.Reader) ([]types.Library, error) {
	var libs []types.Library
	uniqueLibs := make(map[string]string)

	goModData, err := io.ReadAll(r)
	if err != nil {
		return nil, xerrors.Errorf("file read error: %w", err)
	}

	modFileParsed, err := modfile.Parse("go.mod", goModData, nil)
	if err != nil {
		return nil, err
	}

	for i := range modFileParsed.Require {
		uniqueLibs[modFileParsed.Require[i].Mod.Path] = modFileParsed.Require[i].Mod.Version[1:]
	}

	for i := range modFileParsed.Replace {
		// Check if replaced path is actually in our libs.
		if _, ok := uniqueLibs[modFileParsed.Replace[i].Old.Path]; !ok {
			continue
		}

		// If the replace directive has a version on the left side, make sure it matches the version that was imported.
		if modFileParsed.Replace[i].Old.Version != "" && uniqueLibs[modFileParsed.Replace[i].Old.Path] != modFileParsed.Replace[i].Old.Version[1:] {
			continue
		}

		// Only support replace directive with version on the right side.
		// Directive without version is a local path.
		if modFileParsed.Replace[i].New.Version == "" {
			// Delete old lib, since it's a local path now.
			delete(uniqueLibs, modFileParsed.Replace[i].Old.Path)
			continue
		}

		// Delete old lib, in case the path has changed.
		delete(uniqueLibs, modFileParsed.Replace[i].Old.Path)

		// Add replaced library to libary register.
		uniqueLibs[modFileParsed.Replace[i].New.Path] = modFileParsed.Replace[i].New.Version[1:]
	}

	for k, v := range uniqueLibs {
		libs = append(libs, types.Library{
			Name:    k,
			Version: v,
		})
	}

	return libs, nil
}
