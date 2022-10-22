package include

import (
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type Include struct {
	Project string `yaml:"project,omitempty"`
	Ref     string `yaml:"ref,omitempty"`
}

type GitlabCiFile struct {
	Includes []Include `yaml:"include,omitempty"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var gitlabCiFile GitlabCiFile
	decoder := yaml.NewDecoder(r)
	err := decoder.Decode(&gitlabCiFile)
	if err != nil {
		// Currently only parses data when we can unmarshal from array project includes
		// See https://docs.gitlab.com/ee/ci/yaml/includes.html for other options
		return nil, nil, xerrors.Errorf("failed to parse gitlab-ci file: %w", err)
	}

	libs, deps := p.parse(&gitlabCiFile)

	return libs, deps, nil
}

func (p *Parser) parse(gitlabCiFile *GitlabCiFile) ([]types.Library, []types.Dependency) {
	var libs []types.Library

	for _, include := range gitlabCiFile.Includes {
		name := include.Project
		if name == "" {
			continue
		}

		version := include.Ref
		if version == "" {
			version = "latest"
		}

		libs = append(libs, types.Library{
			ID:      utils.PackageID(name, version),
			Name:    name,
			Version: version,
		})
	}

	return libs, nil
}
