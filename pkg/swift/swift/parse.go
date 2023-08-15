package swift

import (
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/liamg/jfather"
	"golang.org/x/xerrors"
	"io"
	"sort"
	"strings"
)

// Parser is a parser for Package.resolved files
type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockFile LockFile
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("read error: %w", err)
	}
	if err := jfather.Unmarshal(input, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	var libs types.Libraries
	for _, pin := range lockFile.Object.Pins {
		libs = append(libs, types.Library{
			Name:    libraryName(pin.RepositoryURL),
			Version: pin.State.Version,
			Locations: []types.Location{
				{
					StartLine: pin.StartLine,
					EndLine:   pin.EndLine,
				},
			},
		})
	}
	sort.Sort(libs)
	return libs, nil, nil
}

func libraryName(name string) string {
	// Swift uses `https://github.com/<author>/<package>.git format
	// `.git` suffix can be omitted (take a look happy test)
	// Remove `https://` and `.git` to fit the same format
	name = strings.TrimPrefix(name, "https://")
	name = strings.TrimSuffix(name, ".git")
	return name
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps for v1
func (p *Pin) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&p); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	p.StartLine = node.Range().Start.Line
	p.EndLine = node.Range().End.Line
	return nil
}
