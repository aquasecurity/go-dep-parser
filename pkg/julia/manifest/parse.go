package julia

import (
	"io"
	"sort"

	"github.com/BurntSushi/toml"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"

	"golang.org/x/xerrors"
)

type Manifest struct {
	JuliaVersion   string                  `toml:"julia_version"`
	ManifestFormat string                  `toml:"manifest_format"`
	Dependencies   map[string][]Dependency `toml:"deps"` // e.g. [[deps.Foo]]
}
type Dependency struct {
	Dependencies []string `toml:"deps"` // by name. e.g. deps = ["Foo"]
	UUID         string   `toml:"uuid"`
	Version      string   `toml:"version"` // not specified for stdlib packages, which are of the Julia version
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var oldDeps map[string][]Dependency
	var man Manifest
	decoder := toml.NewDecoder(r)
	// Try to read the old Manifest format. If that fails, try the new format.
	if _, err := decoder.Decode(&oldDeps); err != nil {
		r.Seek(0, io.SeekStart)
		if _, err := decoder.Decode(&man); err != nil {
			return nil, nil, xerrors.Errorf("decode error: %w", err)
		}
	}

	// We can't know the Julia version on an old manifest.
	// All newer manifests include a manifest version and a julia version.
	if man.ManifestFormat == "" {
		man = Manifest{
			JuliaVersion:   "unknown",
			ManifestFormat: "unknown",
			Dependencies:   oldDeps,
		}
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, nil, xerrors.Errorf("seek error: %w", err)
	}

	// naive parser to get line numbers
	pkgParser := naivePkgParser{r: r}
	lineNumIdx := pkgParser.parse()

	var libs []types.Library
	var deps []types.Dependency
	for name, manifestDeps := range man.Dependencies {
		if len(manifestDeps) > 1 {
			return nil, nil, xerrors.Errorf("multiple entries for dep: %s", name)
		}
		manifestDep := manifestDeps[0]
		version := depVersion(manifestDep, man.JuliaVersion)
		pkgID := utils.PackageID(manifestDep.UUID, version)
		lib := types.Library{
			ID:      pkgID,
			Name:    name,
			Version: version,
		}
		if pos, ok := lineNumIdx[manifestDep.UUID]; ok {
			lib.Locations = []types.Location{{StartLine: pos.start, EndLine: pos.end}}
		}

		libs = append(libs, lib)
		dep := parseDependencies(pkgID, manifestDep, man.Dependencies, man.JuliaVersion)
		if dep != nil {
			deps = append(deps, *dep)
		}
	}
	sort.Sort(types.Libraries(libs))
	sort.Sort(types.Dependencies(deps))
	return libs, deps, nil
}

// Returns the dependencies in `deps` of the given `dep`. If there are no dependencies, returns `nil`.
func parseDependencies(pkgId string, dep Dependency, deps map[string][]Dependency, juliaVersion string) *types.Dependency {
	var dependOn []string

	for _, pkgDep := range dep.Dependencies {
		dep := deps[pkgDep][0]
		version := depVersion(dep, juliaVersion)
		dependOn = append(dependOn, utils.PackageID(dep.UUID, version))
	}
	if len(dependOn) > 0 {
		sort.Strings(dependOn)
		return &types.Dependency{
			ID:        pkgId,
			DependsOn: dependOn,
		}
	} else {
		return nil
	}
}

// Returns the effective version of the `dep`.
// stdlib packages do not have a version in the manifest because they are packaged with julia itself
func depVersion(dep Dependency, juliaVersion string) string {
	if len(dep.Version) == 0 {
		return juliaVersion
	}
	return dep.Version
}
