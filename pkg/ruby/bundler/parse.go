package bundler

import (
	"bufio"
	"strings"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"

	"golang.org/x/xerrors"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var libs []types.Library
	var dependsOn []string
	var deps []types.Dependency = make([]types.Dependency, 0)
	var lib types.Library
	var versions = make(map[string]string)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if countLeadingSpace(line) == 4 {
			if len(dependsOn) > 0 {
				deps = append(deps, types.Dependency{ID: lib.ID, DependsOn: dependsOn})
			}
			dependsOn = make([]string, 0) //re-initialize
			line = strings.TrimSpace(line)
			s := strings.Fields(line)
			if len(s) != 2 {
				continue
			}
			version := strings.Trim(s[1], "()")          // drop parentheses
			version = strings.SplitN(version, "-", 2)[0] // drop platform (e.g. 1.13.6-x86_64-linux => 1.13.6)
			lib = types.Library{
				ID:      utils.PackageID(s[0], version),
				Name:    s[0],
				Version: version,
			}
			versions[s[0]] = version
			libs = append(libs, lib)
		}
		if countLeadingSpace(line) == 6 {
			line = strings.TrimSpace(line)
			s := strings.Fields(line)
			dependsOn = append(dependsOn, s[0]) //store name only for now
		}
	}
	//append last dependency (if any)
	if len(dependsOn) > 0 {
		deps = append(deps, types.Dependency{ID: lib.ID, DependsOn: dependsOn})
	}
	for i, dep := range deps {
		dependsOn = make([]string, 0)
		for _, pkgName := range dep.DependsOn {
			if version, ok := versions[pkgName]; ok {
				dependsOn = append(dependsOn, utils.PackageID(pkgName, version))
			}
		}
		deps[i].DependsOn = dependsOn
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, xerrors.Errorf("scan error: %w", err)
	}
	return libs, deps, nil
}

func countLeadingSpace(line string) int {
	i := 0
	for _, runeValue := range line {
		if runeValue == ' ' {
			i++
		} else {
			break
		}
	}
	return i
}
