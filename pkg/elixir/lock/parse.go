package lock

import (
	"bufio"
	"fmt"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"strings"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var libs []types.Library
	scanner := bufio.NewScanner(r)
	var lineNumber int // It is used to save dependency location
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "}") { // skip 1st and last lines
			continue
		}

		// dependency format:
		// "<depName>": {<:hex|:git>, :<depName>, "<depVersion>", "<checksum>", [:mix], [<required deps>], hexpm", "<checksum>"},
		ss := strings.Split(line, ", ")
		if len(ss) < 8 { // In the case where <required deps> array is empty: s == 8, in other cases s > 8
			// git repository doesn't have dependency version
			// skip these dependencies
			if !strings.Contains(ss[0], ":git") {
				log.Logger.Warnf("Cannot parse dependency from: %s", line)
			}
			continue
		}
		name := strings.TrimLeft(ss[1], ":")
		version := strings.Trim(ss[2], "\"")
		libs = append(libs, types.Library{
			ID:        fmt.Sprintf("%s@%s", name, version),
			Name:      name,
			Version:   version,
			Locations: []types.Location{{StartLine: lineNumber, EndLine: lineNumber}},
		})

	}
	return utils.UniqueLibraries(libs), nil, nil
}
