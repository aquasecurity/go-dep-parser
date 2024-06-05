package lockfile

import (
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/liamg/jfather"
	"golang.org/x/xerrors"
	"io"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockfile sbtLockfile
	input, err := io.ReadAll(r)

	if err != nil {
		return nil, nil, xerrors.Errorf("failed to read sbt lockfile: %w", err)
	}
	if err := jfather.Unmarshal(input, &lockfile); err != nil {
		return nil, nil, xerrors.Errorf("JSON decoding failed: %w", err)
	}

	var libraries []types.Library

	for _, dependency := range lockfile.Dependencies {
		libraries = append(libraries, types.Library{
			ID:        dependency.Organization + ":" + dependency.Name + ":" + dependency.Version,
			Name:      dependency.Organization + ":" + dependency.Name,
			Version:   dependency.Version,
			Locations: []types.Location{{StartLine: dependency.StartLine, EndLine: dependency.EndLine}},
		})
	}

	return libraries, nil, nil
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (t *sbtLockfileDependency) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}

// lockfile format defined at: https://stringbean.github.io/sbt-dependency-lock/file-formats/version-1.html
type sbtLockfile struct {
	Version        int                     `json:"lockVersion"`
	Timestamp      string                  `json:"timestamp"`
	Configurations []string                `json:"configurations"`
	Dependencies   []sbtLockfileDependency `json:"dependencies"`
}

type sbtLockfileDependency struct {
	Organization   string                `json:"org"`
	Name           string                `json:"name"`
	Version        string                `json:"version"`
	Artifacts      []sbtLockfileArtifact `json:"artifacts"`
	Configurations []string              `json:"configurations"`
	StartLine      int
	EndLine        int
}

type sbtLockfileArtifact struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}
