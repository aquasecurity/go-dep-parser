package lock

import (
	"fmt"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

const (
	idFormat      = "%s@%s"
	transitiveDep = "transitive"
)

// Parser is a parser for pubspec.lock
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
		return nil, nil, xerrors.Errorf("failed to decode pubspec.lock file: %w", err)
	}
	var libs []types.Library
	for name, dep := range l.Packages {
		lib := types.Library{
			ID:       pkgID(name, dep.Version),
			Name:     name,
			Version:  dep.Version,
			Indirect: dep.Dependency == transitiveDep,
		}
		libs = append(libs, lib)
	}

	return libs, nil, nil
}

func pkgID(name, version string) string {
	return fmt.Sprintf(idFormat, name, version)
}
