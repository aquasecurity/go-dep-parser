package types

import dio "github.com/aquasecurity/go-dep-parser/pkg/io"

type Library struct {
	Name     string
	Version  string
	Indirect bool   `json:",omitempty"`
	License  string `json:",omitempty"`
}

type Dependency struct {
	ID        string
	DependsOn []string
}

type Parser interface {
	ID(pkgName, version string) string
	Parse(r dio.ReadSeekerAt) ([]Library, []Dependency, error)
}

type DefaultParser struct{}

func (p *DefaultParser) ID(pkgName, version string) string {
	return ""
}
