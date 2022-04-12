package mod

import (
	"io"
	"strconv"
	"strings"

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
		return nil, xerrors.Errorf("go.mod parse error: %w", err)
	}

	skipIndirect := lessThan117(modFileParsed.Go.Version)

	for _, require := range modFileParsed.Require {
		// Skip indirect dependencies less than Go 1.17
		if skipIndirect && require.Indirect {
			continue
		}
		uniqueLibs[require.Mod.Path] = require.Mod.Version[1:]
	}

	for _, replace := range modFileParsed.Replace {
		// Check if replaced path is actually in our libs.
		if _, ok := uniqueLibs[replace.Old.Path]; !ok {
			continue
		}

		// If the replace directive has a version on the left side, make sure it matches the version that was imported.
		if replace.Old.Version != "" && uniqueLibs[replace.Old.Path] != replace.Old.Version[1:] {
			continue
		}

		// Only support replace directive with version on the right side.
		// Directive without version is a local path.
		if replace.New.Version == "" {
			// Delete old lib, since it's a local path now.
			delete(uniqueLibs, replace.Old.Path)
			continue
		}

		// Delete old lib, in case the path has changed.
		delete(uniqueLibs, replace.Old.Path)

		// Add replaced library to library register.
		uniqueLibs[replace.New.Path] = replace.New.Version[1:]
	}

	for k, v := range uniqueLibs {
		libs = append(libs, types.Library{
			Name:    k,
			Version: v,
		})
	}

	return libs, nil
}

// Check if the Go version is less than 1.17
func lessThan117(ver string) bool {
	ss := strings.Split(ver, ".")
	if len(ss) != 2 {
		return false
	}
	major, err := strconv.Atoi(ss[0])
	if err != nil {
		return false
	}
	minor, err := strconv.Atoi(ss[1])
	if err != nil {
		return false
	}

	return major <= 1 && minor < 17
}
