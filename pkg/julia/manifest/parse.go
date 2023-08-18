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

type PrimitiveManifest struct {
	JuliaVersion   string                           `toml:"julia_version"`
	ManifestFormat string                           `toml:"manifest_format"`
	Dependencies   map[string][]PrimitiveDependency `toml:"deps"` // e.g. [[deps.Foo]]
}

type DecodedManifest struct {
	JuliaVersion   string
	ManifestFormat string
	Dependencies   map[string][]DecodedDependency
}

type PrimitiveDependency struct {
	Dependencies toml.Primitive `toml:"deps"` // by name. e.g. deps = ["Foo"] or [deps.Foo.deps]
	UUID         string         `toml:"uuid"`
	Version      string         `toml:"version"` // not specified for stdlib packages, which are of the Julia version
}

type DecodedDependency struct {
	Dependencies map[string]*string
	UUID         string
	Version      string
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var oldDeps map[string][]PrimitiveDependency
	var primMan PrimitiveManifest
	var manMetadata toml.MetaData
	decoder := toml.NewDecoder(r)
	// Try to read the old Manifest format. If that fails, try the new format.
	if _, err := decoder.Decode(&oldDeps); err != nil {
		if _, err = r.Seek(0, io.SeekStart); err != nil {
			return nil, nil, xerrors.Errorf("seek error: %w", err)
		}
		if manMetadata, err = decoder.Decode(&primMan); err != nil {
			return nil, nil, xerrors.Errorf("decode error: %w", err)
		}
	}

	// We can't know the Julia version on an old manifest.
	// All newer manifests include a manifest version and a julia version.
	if primMan.ManifestFormat == "" {
		primMan = PrimitiveManifest{
			JuliaVersion: "unknown",
			Dependencies: oldDeps,
		}
	}

	man, err := decodeManifest(&primMan, &manMetadata)
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to decode manifest dependencies: %w", err)
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
		for _, manifestDep := range manifestDeps {
			version := depVersion(&manifestDep, man.JuliaVersion)
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

			dep, err := parseDependencies(pkgID, manifestDep.Dependencies, man.Dependencies, man.JuliaVersion)
			if err != nil {
				return nil, nil, xerrors.Errorf("failed to parse dependencies: %w", err)
			}
			if dep != nil {
				deps = append(deps, *dep)
			}
		}
	}
	sort.Sort(types.Libraries(libs))
	sort.Sort(types.Dependencies(deps))
	return libs, deps, nil
}

// Returns the matching dependencies in `allDeps` of the given `deps`. If there are no matching dependencies, returns `nil`.
func parseDependencies(pkgId string, deps map[string]*string, allDeps map[string][]DecodedDependency, juliaVersion string) (*types.Dependency, error) {
	var dependOn []string

	for depName, depUUID := range deps {
		dep, err := lookupDep(depName, depUUID, allDeps)
		if err != nil {
			return nil, err
		}
		version := depVersion(dep, juliaVersion)
		dependOn = append(dependOn, utils.PackageID(dep.UUID, version))
	}

	if len(dependOn) > 0 {
		sort.Strings(dependOn)
		return &types.Dependency{
			ID:        pkgId,
			DependsOn: dependOn,
		}, nil
	} else {
		return nil, nil
	}
}

// Returns the matching dependency in `allDeps` given the dep with the `name` and `uuid`.
// The `uuid` may be `nil` if the given dep is the only one with its name in the manifest.
// Otherwise, if there are multiple deps with the same name, the `uuid` must be specified.
func lookupDep(name string, uuid *string, allDeps map[string][]DecodedDependency) (*DecodedDependency, error) {
	if uuid == nil {
		// No UUID was set in the manifest, which means there is only one dep with this name
		return &allDeps[name][0], nil
	} else {
		for _, candidateDep := range allDeps[name] {
			if candidateDep.UUID == *uuid {
				return &candidateDep, nil
			}
		}
		return nil, xerrors.Errorf("failed to find dep with name %s and UUID %s", name, *uuid)
	}
}

// Returns the effective version of the `dep`.
// stdlib packages do not have a version in the manifest because they are packaged with julia itself
func depVersion(dep *DecodedDependency, juliaVersion string) string {
	if len(dep.Version) == 0 {
		return juliaVersion
	}
	return dep.Version
}

// Decodes a primitive manifest using the metadata from parse time.
func decodeManifest(man *PrimitiveManifest, metadata *toml.MetaData) (*DecodedManifest, error) {
	// Copy over already decoded fields
	decodedManifest := DecodedManifest{
		JuliaVersion:   man.JuliaVersion,
		ManifestFormat: man.ManifestFormat,
		Dependencies:   make(map[string][]DecodedDependency),
	}

	// Decode each dependency into the new manifest
	for depName, primDeps := range man.Dependencies {
		decodedDeps := []DecodedDependency{}
		for _, primDep := range primDeps {
			decodedDep, err := decodeDependency(&primDep, metadata)
			if err != nil {
				return nil, err
			}
			decodedDeps = append(decodedDeps, *decodedDep)
		}
		decodedManifest.Dependencies[depName] = decodedDeps
	}

	return &decodedManifest, nil
}

// Decodes a primitive dependency using the metadata from parse time.
func decodeDependency(dep *PrimitiveDependency, metadata *toml.MetaData) (*DecodedDependency, error) {
	// Try to decode as []string first where the manifest looks like deps = ["A", "B"]
	var possibleDeps []string
	err := metadata.PrimitiveDecode(dep.Dependencies, &possibleDeps)
	if err == nil {
		finalDeps := make(map[string]*string)
		for _, depName := range possibleDeps {
			finalDeps[depName] = nil
		}
		return &DecodedDependency{
			Dependencies: finalDeps,
			UUID:         dep.UUID,
			Version:      dep.Version,
		}, nil
	}

	// The other possibility is a map where the manifest looks like
	// [deps.A.deps]
	// B = "..."
	var possibleDepsMap map[string]*string
	err = metadata.PrimitiveDecode(dep.Dependencies, &possibleDepsMap)
	if err == nil {
		return &DecodedDependency{
			Dependencies: possibleDepsMap,
			UUID:         dep.UUID,
			Version:      dep.Version,
		}, nil
	}

	// We don't know what the shape of the data is -- i.e. an invalid manifest
	return nil, err
}
