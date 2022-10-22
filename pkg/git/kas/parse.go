package kas

import (
	"fmt"
	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	giturls "github.com/whilp/git-urls"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type Repo struct {
	Url     string `yaml:"url,omitempty"`
	RefSpec string `yaml:"refspec,omitempty"`
}

type KasFile struct {
	Repos map[string]Repo `yaml:"repos,omitempty"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var kasFile KasFile
	decoder := yaml.NewDecoder(r)
	err := decoder.Decode(&kasFile)
	if err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	libs, deps := p.parse(&kasFile)

	return libs, deps, nil
}

func (p *Parser) parse(kasFile *KasFile) ([]types.Library, []types.Dependency) {
	var libs []types.Library

	for _, repo := range kasFile.Repos {
		name := getRepoNamefromUri(repo.Url)
		if name == "" || repo.Url == "" {
			continue
		}

		version := repo.RefSpec
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

func getRepoNamefromUri(rawUri string) string {
	uri, err := giturls.Parse(rawUri)
	if err != nil {
		return ""
	}

	name := strings.TrimSuffix(uri.Path, ".git")
	name = strings.TrimLeft(name, "/")
	return fmt.Sprintf("%s/%s", uri.Host, name)
}
