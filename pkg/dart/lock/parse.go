package lock

import (
	"fmt"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
	"strings"
)

const (
	idFormat      = "%s@%s"
	directMainDep = "direct main"
	directDevDep  = "direct dev"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

type lock struct {
	Packages map[string]Dep `yaml:"packages"`
}

type Dep struct {
	Dependency string `yaml:"dependency"`
	Version    string `yaml:"version"`
}

func (Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	l := &lock{}
	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&l); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode pubspec.lock file: %s", err.Error())
	}
	var libs []types.Library
	for name, dep := range l.Packages {
		lib := types.Library{
			ID:      fmt.Sprintf(idFormat, name, dep.Version),
			Name:    name,
			Version: dep.Version,
			// there are 3 types of dependency fields:
			// "direct main", "direct dev" and transitive
			// transitive non-string field
			// so find Indirect dependencies using "direct main" and "direct dev" fields
			Indirect: dep.Dependency != directDevDep && dep.Dependency != directMainDep,
		}
		libs = append(libs, lib)
	}

	return libs, nil, nil
}

func parseDep(dep string) (types.Library, error) {
	// dep example:
	// 'AppCenter (4.2.0)'
	// direct dep examples:
	// 'AppCenter/Core'
	// 'AppCenter/Analytics (= 4.2.0)'
	// 'AppCenter/Analytics (-> 4.2.0)'
	ss := strings.Split(dep, " (")
	if len(ss) != 2 {
		return types.Library{}, xerrors.Errorf("Unable to determine cocoapods dependency: %q", dep)
	}

	name := ss[0]
	version := strings.Trim(strings.TrimSpace(ss[1]), "()")
	lib := types.Library{
		ID:      pkgID(name, version),
		Name:    name,
		Version: version,
	}

	return lib, nil
}

func pkgID(name, version string) string {
	return fmt.Sprintf(idFormat, name, version)
}
