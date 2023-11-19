package sum

import (
	"bufio"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/golang/mod"
	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

type VersionWithMetadata struct {
	Version    string
	LineNumber int
}

// Parse parses a go.sum file
func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var libs []types.Library
	uniqueLibs := make(map[string]VersionWithMetadata)

	scanner := bufio.NewScanner(r)
	var lineNumber int // It is used to save dependency location
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		s := strings.Fields(line)
		if len(s) < 2 {
			continue
		}

		// go.sum records and sorts all non-major versions
		// with the latest version as last entry
		uniqueLibs[s[0]] = VersionWithMetadata{
			Version:    strings.TrimSuffix(strings.TrimPrefix(s[1], "v"), "/go.mod"),
			LineNumber: lineNumber,
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, xerrors.Errorf("scan error: %w", err)
	}

	for k, v := range uniqueLibs {
		libs = append(libs, types.Library{
			ID:        mod.ModuleID(k, v.Version),
			Name:      k,
			Version:   v.Version,
			Locations: []types.Location{{StartLine: v.LineNumber, EndLine: v.LineNumber}},
		})
	}

	return libs, nil, nil
}
