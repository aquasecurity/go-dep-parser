package pnpm

import (
	"fmt"
	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

type PackageResolution struct {
	Integrity string `yaml:"integrity"`
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
}

type LockFile struct {
	LockfileVersion      int8                   `yaml:"lockfileVersion"`
	Importers            map[string]PackageInfo `yaml:"importers,omitempty"`
	Specifiers           map[string]string      `yaml:"specifiers,omitempty"`
	Dependencies         map[string]string      `yaml:"dependencies,omitempty"`
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

	for pkg, info := range lockFile.Packages {
		if info.IsDev {
			continue
		}

		dependencies := make([]string, 0)
		name, version := getPackageNameAndVersion(pkg, lockFile.LockfileVersion)
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

func isIndirectLib(name string, directDeps map[string]string) bool {
	_, ok := directDeps[name]
	return !ok
}

func getPackageNameAndVersion(pkg string, lockFileVersion int8) (string, string) {
	if lockFileVersion < 6 {
		return getPackageNameAndVersionV5(pkg)
	}
	return getPackageNameAndVersionV6(pkg)
}

// 2 package formats are possible:
// relative path: `/<pkg_name>/<pkg_version>` e.g. /foo/1.0.0
// registry: `<registry_url>/<pkg_name>/<pkg_version>` e.g. registry.node-modules.io/foo/1.0.0
// https://github.com/pnpm/spec/blob/master/lockfile/5.2.md#packages
//
// `pkg_name` has 2 formats:
// with slash - @<author>/<name>. e.g. `/@babel/generator/7.21.9`
// without slash - <name>. e.g. `/lodash/4.17.10`
//
// `pkg_version` can contain peer deps. <pkg_name>/<pkg_version>_<peer_deps>
// e.g. /@babel/helper-compilation-targets/7.21.5_@babel+core@7.21.8
func getPackageNameAndVersionV5(pkg string) (string, string) {
	s := strings.Split(pkg, "/")
	// take name as last element before version
	name := s[len(s)-2]
	// if previous element start from `@` => this is name with slash
	if strings.HasPrefix(s[len(s)-3], "@") {
		name = strings.Join(s[len(s)-3:len(s)-1], "/")
	}

	version := s[len(s)-1]
	// trim peer deps
	if strings.Contains(version, "_") {
		version = version[:strings.Index(version, "_")]
	}
	return name, version
}

//	2 package formats are possible:
//
// relative path: `/<pkg_name>@<pkg_version>` e.g. /foo@1.0.0
// registry: `<registry_url>/<pkg_name>@<pkg_version>` e.g. registry.node-modules.io/foo@1.0.0
// https://github.com/pnpm/pnpm/pull/5810
// https://github.com/pnpm/spec/issues/4#issuecomment-1558891433
//
// `pkg_name` has 2 formats:
// with slash - @<author>@<name>. e.g. `/@babel/generator@7.21.9`
// without slash - <name>. e.g. `/lodash@4.17.10`
//
// `pkg_version` can contain peer deps. <pkg_name>@<pkg_version>(<peer_deps>)
// e.g. /@babel/helper-compilation-targets@7.21.5(@babel+core@7.21.8)
func getPackageNameAndVersionV6(pkg string) (string, string) {
	// trim peer deps to avoid false splitting by `@`
	if strings.Contains(pkg, "(") {
		pkg = pkg[:strings.Index(pkg, "(")]
	}
	// remove first `/`
	pkg = strings.TrimLeft(pkg, "/")

	name := pkg[:strings.LastIndex(pkg, "@")]
	version := pkg[strings.LastIndex(pkg, "@")+1:]

	s := strings.Split(name, "/")
	if len(s) >= 2 {
		name = s[len(s)-1]
		// if previous element start from `@` => this is name with slash
		if strings.HasPrefix(s[len(s)-2], "@") {
			name = strings.Join(s[len(s)-2:], "/")
		}
	}

	return name, version
}
