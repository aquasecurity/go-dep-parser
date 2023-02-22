package poetry

import (
	"github.com/BurntSushi/toml"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
	"golang.org/x/xerrors"
	"sort"
	"strings"

	version "github.com/aquasecurity/go-pep440-version"
)

type Lockfile struct {
	Packages []struct {
		Category       string                 `toml:"category"`
		Description    string                 `toml:"description"`
		Marker         string                 `toml:"marker,omitempty"`
		Name           string                 `toml:"name"`
		Optional       bool                   `toml:"optional"`
		PythonVersions string                 `toml:"python-versions"`
		Version        string                 `toml:"version"`
		Dependencies   map[string]interface{} `toml:"dependencies"`
		Metadata       interface{}
	} `toml:"package"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockfile Lockfile
	if _, err := toml.NewDecoder(r).Decode(&lockfile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode poetry.lock: %w", err)
	}

	// dependencies of libraries use version range
	// store all installed versions of libraries for use in dependsOn
	libsVersions := map[string][]string{}
	for _, pkg := range lockfile.Packages {
		if pkg.Category == "dev" {
			continue
		}
		vers, ok := libsVersions[pkg.Name]
		if ok {
			libsVersions[pkg.Name] = append(vers, pkg.Version)
			continue
		}
		libsVersions[pkg.Name] = []string{pkg.Version}
	}

	var libs []types.Library
	var deps []types.Dependency
	for _, pkg := range lockfile.Packages {
		if pkg.Category == "dev" {
			continue
		}
		libs = append(libs, types.Library{
			ID:      utils.PackageID(pkg.Name, pkg.Version),
			Name:    pkg.Name,
			Version: pkg.Version,
		})
		var dependsOn []string
		for name, versRange := range pkg.Dependencies {
			dep, err := parseDependency(name, versRange, libsVersions)
			if err != nil {
				log.Logger.Debugf("failed to parse poetry dependency: %s", err)
			}
			if dep != "" {
				dependsOn = append(dependsOn, dep)
			}
		}
		if len(dependsOn) > 0 {
			sort.Slice(dependsOn, func(i, j int) bool {
				return dependsOn[i] < dependsOn[j]
			})
			deps = append(deps, types.Dependency{
				ID:        utils.PackageID(pkg.Name, pkg.Version),
				DependsOn: dependsOn,
			})
		}
	}
	return libs, deps, nil
}

func parseDependency(name string, versRange interface{}, libsVersions map[string][]string) (string, error) {
	name = handlePackageName(name)
	vers, ok := libsVersions[name]
	if ok {
		for _, ver := range vers {
			var vRange string

			switch r := versRange.(type) {
			case string:
				vRange = r
			case map[string]interface{}:
				for k, v := range r {
					if k == "version" {
						vRange = v.(string)
					}
				}
			}

			matched, err := matchVersion(ver, vRange)
			if err != nil {
				return "", xerrors.Errorf("failed to match version for %s: %w", name, err)
			}
			if matched {
				return utils.PackageID(name, ver), nil
			}
		}
	}
	return "", xerrors.Errorf("failed to find version for %q", name)
}

// matchVersion checks if the package version satisfies the given constraint.
func matchVersion(currentVersion, constraint string) (bool, error) {
	v, err := version.Parse(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("python version error (%s): %s", currentVersion, err)
	}

	c, err := version.NewSpecifiers(constraint, version.WithPreRelease(true))
	if err != nil {
		return false, xerrors.Errorf("python constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}

func handlePackageName(name string) string {
	// Library names doesn't use `_`, `.` or upper case
	// But Dependency struct can contain them
	// We need to fix this
	name = strings.ToLower(name)              // e.g. https://github.com/python-poetry/poetry/blob/c8945eb110aeda611cc6721565d7ad0c657d453a/poetry.lock#L819
	name = strings.ReplaceAll(name, "_", "-") // e.g. https://github.com/python-poetry/poetry/blob/c8945eb110aeda611cc6721565d7ad0c657d453a/poetry.lock#L50
	name = strings.ReplaceAll(name, ".", "-") // e.g. https://github.com/python-poetry/poetry/blob/c8945eb110aeda611cc6721565d7ad0c657d453a/poetry.lock#L816
	return name
}
