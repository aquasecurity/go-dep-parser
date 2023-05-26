package pnpm

import (
	"fmt"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"strconv"

	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-version/pkg/semver"
)

type PackageResolution struct {
	Integrity string `yaml:"integrity"`
	Tarball   string `yaml:"tarball,omitempty"`
}

type PackageInfo struct {
	Resolution           PackageResolution `yaml:"resolution"`
	Engines              map[string]string `yaml:"engines,omitempty"`
	Specifiers           map[string]string `yaml:"specifiers,omitempty"`
	Dependencies         map[string]string `yaml:"dependencies,omitempty"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies,omitempty"`
	DevDependencies      map[string]string `yaml:"devDependencies,omitempty"`
	IsDev                bool              `yaml:"dev,omitempty"`
	IsOptional           bool              `yaml:"optional,omitempty"`
	Name                 string            `yaml:"name,omitempty"`
	Version              string            `yaml:"version,omitempty"`
}

type LockFile struct {
	LockfileVersion      interface{}            `yaml:"lockfileVersion"`
	Importers            map[string]PackageInfo `yaml:"importers,omitempty"`
	Specifiers           map[string]string      `yaml:"specifiers,omitempty"`
	Dependencies         map[string]interface{} `yaml:"dependencies,omitempty"`
	OptionalDependencies map[string]string      `yaml:"optionalDependencies,omitempty"`
	DevDependencies      map[string]string      `yaml:"devDependencies,omitempty"`
	Packages             map[string]PackageInfo `yaml:"packages,omitempty"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) ID(name, version string) string {
	return fmt.Sprintf("%s@%s", name, version)
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockFile LockFile
	decoder := yaml.NewDecoder(r)
	err := decoder.Decode(&lockFile)
	if err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	libs, deps := p.parse(&lockFile)

	return libs, deps, nil
}

func (p *Parser) parse(lockFile *LockFile) ([]types.Library, []types.Dependency) {
	var libs []types.Library
	var deps []types.Dependency

	var lockVer float64
	switch v := lockFile.LockfileVersion.(type) {
	// v5
	case float64:
		lockVer = v
	// v6+
	case string:
		var err error
		if lockVer, err = strconv.ParseFloat(v, 64); err != nil {
			log.Logger.Debugf("Unable to convert lock file version: %s", err)
			return nil, nil
		}
	default:
		log.Logger.Debugf("Unable to convert lock file version: %s", lockFile.LockfileVersion)
		return nil, nil
	}

	for pkg, info := range lockFile.Packages {
		if info.IsDev {
			continue
		}

		dependencies := make([]string, 0)
		// packages from tarball have `name` and `version` fields
		name := info.Name
		version := info.Version
		// for other packages, these fields do not exist. Parse depPath to determine name and version
		if info.Resolution.Tarball == "" {
			name, version = getPackageNameAndVersion(pkg, lockVer)
		}
		id := p.ID(name, version)

		for depName, depVer := range info.Dependencies {
			dependencies = append(dependencies, p.ID(depName, depVer))
		}

		libs = append(libs, types.Library{
			ID:       id,
			Name:     name,
			Version:  version,
			Indirect: isIndirectLib(name, lockFile.Dependencies),
		})

		if len(dependencies) > 0 {
			deps = append(deps, types.Dependency{
				ID:        id,
				DependsOn: dependencies,
			})
		}
	}

	return libs, deps
}

func isIndirectLib(name string, directDeps map[string]interface{}) bool {
	_, ok := directDeps[name]
	return !ok
}

// cf. https://github.com/pnpm/pnpm/blob/ce61f8d3c29eee46cee38d56ced45aea8a439a53/packages/dependency-path/src/index.ts#L112-L163
func getPackageNameAndVersion(depPath string, lockFileVersion float64) (string, string) {
	versionSep := "@"
	if lockFileVersion < 6 {
		versionSep = "/"
	}
	return parsePackage(depPath, versionSep)
}
func parsePackage(pkg, versionSep string) (string, string) {
	// Skip registry
	// e.g.
	//    - "registry.npmjs.org/lodash/4.17.10" => "lodash/4.17.10"
	//    - "registry.npmjs.org/@babel/generator/7.21.9" => "@babel/generator/7.21.9"
	//    - "/lodash/4.17.10" => "lodash/4.17.10"
	_, pkg, _ = strings.Cut(pkg, "/")
	// Parse namespace(?)
	// e.g.
	//    - v5:  "@babel/generator/7.21.9" => {"babel", "generator/7.21.9"}
	//    - v6+: "@babel/helper-annotate-as-pure@7.18.6" => "{"babel", "helper-annotate-as-pure@7.18.6"}
	var namespace string
	if strings.HasPrefix(pkg, "@") {
		namespace, pkg, _ = strings.Cut(pkg, "/")
	}
	// Parse package name
	// e.g.
	//    - v5:  "generator/7.21.9" => {"generator", "7.21.9"}
	//    - v6+: "helper-annotate-as-pure@7.18.6" => {"helper-annotate-as-pure", "7.18.6"}
	var name, version string
	name, version, _ = strings.Cut(pkg, versionSep)
	if namespace != "" {
		name = fmt.Sprintf("%s/%s", namespace, name)
	}
	// Trim peer deps
	// e.g.
	//    - v5:  "7.21.5_@babel+core@7.21.8" => "7.21.5"
	//    - v6+: "7.21.5(@babel/core@7.20.7)" => "7.21.5"
	if idx := strings.IndexAny(version, "_("); idx != -1 {
		version = version[:idx]
	}
	if _, err := semver.Parse(version); err != nil {
		log.Logger.Debugf("Skip %q package. %q doesn't match semver: %s", pkg, version, err)
		return "", ""
	}
	return name, version
}
