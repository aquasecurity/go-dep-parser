package yarn

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
)

var (
	yarnLocatorRegexp    = regexp.MustCompile(`^\s?\\?"?(?P<package>\S+?)@(?:(?P<protocol>\S+?):)?(?P<version>.+?)\\?"?:?$`)
	yarnVersionRegexp    = regexp.MustCompile(`^"?version:?"?\s+"?(?P<version>[^"]+)"?`)
	yarnDependencyRegexp = regexp.MustCompile(`"?(?P<package>.+?)"?:?\s"?(?P<version>[^"]+)"?`)
)

type LockFile struct {
	Dependencies map[string]Dependency
}

type Library struct {
	Locators []string
	Name     string
	Version  string
	Location types.Location
}
type Dependency struct {
	Locator string
	Name    string
}

var lineNumber int

func parseLocator(target string) (packagename, protocol, version string, err error) {
	capture := yarnLocatorRegexp.FindStringSubmatch(target)
	if len(capture) < 3 {
		return "", "", "", xerrors.New("not package format")
	}
	for i, group := range yarnLocatorRegexp.SubexpNames() {
		switch group {
		case "package":
			packagename = capture[i]
		case "protocol":
			protocol = capture[i]
		case "version":
			version = capture[i]
		}
	}
	return
}

func parsePackageLocators(target string) (packagename, protocol string, locs []string, err error) {
	locsSplit := strings.Split(target, ", ")
	packagename, protocol, _, err = parseLocator(locsSplit[0])
	if err != nil {
		return "", "", nil, err
	}
	locs = lo.Map(locsSplit, func(loc string, _ int) string {
		_, _, version, _ := parseLocator(loc)
		return utils.PackageID(packagename, version)
	})
	return
}

func getVersion(target string) (version string, err error) {
	capture := yarnVersionRegexp.FindStringSubmatch(target)
	if len(capture) < 2 {
		return "", xerrors.New("failed to parse version")
	}
	return capture[len(capture)-1], nil
}

func getDependency(target string) (name, version string, err error) {
	capture := yarnDependencyRegexp.FindStringSubmatch(target)
	if len(capture) < 3 {
		return "", "", xerrors.New("not dependency")
	}
	return capture[1], capture[2], nil
}

func validProtocol(protocol string) (valid bool) {
	switch protocol {
	// only scan npm packages
	case "npm", "":
		return true
	}
	return false
}

func parseResults(yarnLibs map[string]Library, dependsOn map[string][]Dependency) (libs []types.Library, deps []types.Dependency) {
	// find dependencies by locators
	for libLoc, lib := range yarnLibs {
		libs = append(libs, types.Library{
			ID:      utils.PackageID(lib.Name, lib.Version),
			Name:    lib.Name,
			Version: lib.Version,
			Locations: []types.Location{
				lib.Location,
			},
		})

		if libDeps, ok := dependsOn[libLoc]; ok {
			// find resolved version of each dependency
			libDepIds := lo.FilterMap(libDeps, func(dep Dependency, _ int) (string, bool) {
				if depLib, ok := yarnLibs[dep.Locator]; ok {
					return utils.PackageID(depLib.Name, depLib.Version), true
				}
				return "", false
			})
			deps = append(deps, types.Dependency{
				ID:        utils.PackageID(lib.Name, lib.Version),
				DependsOn: libDepIds,
			})
		}
	}

	libs = lo.UniqBy(libs, func(lib types.Library) string {
		return utils.PackageID(lib.Name, lib.Version)
	})

	deps = lo.UniqBy(deps, func(dep types.Dependency) string {
		return dep.ID
	})

	return
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func scanBlocks(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		// We have a full newline-terminated line.
		return i + 2, data[0:i], nil
	} else if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return i + 4, data[0:i], nil
	}

	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}

func scanProperties(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	lineRegex := regexp.MustCompile(`\n\s\s[\w"]`)
	if loc := lineRegex.FindIndex(data); loc != nil {
		// New dependency property line
		return loc[1] - 1, data[0:loc[0]], nil
	}

	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}

func parseBlock(block []byte) (lib Library, deps []Dependency, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(block))
	lib.Location.StartLine, lib.Location.EndLine = calcBlockLineNumbers(block)
	scanner.Split(scanProperties)
	for scanner.Scan() {
		line := scanner.Text()

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Skip this block
		if strings.HasPrefix(line, "__metadata") {
			return
		}

		line = strings.TrimPrefix(line, `"`)

		switch {
		case strings.HasPrefix(line, "version"):
			if version, err := getVersion(line); err != nil {
				return lib, nil, err
			} else {
				lib.Version = version
				continue
			}
		case strings.HasPrefix(line, "dependencies:"):
			// start dependencies block
			if deps, err = parseDependencies(scanner.Bytes()); err != nil {
				return lib, nil, err
			}
			continue
		}

		// try parse package locator
		if name, protocol, locs, err := parsePackageLocators(line); err == nil {
			if locs == nil || !validProtocol(protocol) {
				return lib, nil, xerrors.Errorf("failed to parse package locator")
			} else {
				lib.Locators = locs
				lib.Name = name
				continue
			}
		}
	}

	return
}

func calcBlockLineNumbers(block []byte) (start, end int) {
	// block seperator is 2 line breaks
	lineNumber += 2
	leadingLineBreaks := len(block) - len(bytes.TrimLeft(block, "\n"))
	trailingLineBreaks := len(block) - len(bytes.TrimRight(block, "\n"))
	start = lineNumber + leadingLineBreaks
	end = start + bytes.Count(block, []byte("\n")) - leadingLineBreaks - trailingLineBreaks
	lineNumber = end
	return
}

func parseDependencies(depBlock []byte) (deps []Dependency, err error) {
	scanner := bufio.NewScanner(bytes.NewReader(depBlock))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "dependencies:") {
			continue
		}

		if dep, err := parseDependency(line); err != nil {
			return deps, err
		} else {
			deps = append(deps, dep)
		}
	}

	return
}

func parseDependency(line string) (dep Dependency, err error) {
	line = strings.TrimSpace(line)
	if name, version, err := getDependency(line); err != nil {
		return dep, err
	} else {
		dep.Locator = utils.PackageID(name, version)
		dep.Name = name
	}

	return
}

func (p *Parser) Parse(r dio.ReadSeekerAt) (libs []types.Library, deps []types.Dependency, err error) {
	lineNumber = -1
	scanner := bufio.NewScanner(r)
	scanner.Split(scanBlocks)
	unique := map[string]struct{}{}
	dependsOn := map[string][]Dependency{}
	yarnLibs := map[string]Library{}
	for scanner.Scan() {
		block := scanner.Bytes()
		lib, deps, err := parseBlock(block)
		if err == nil {
			symbol := utils.PackageID(lib.Name, lib.Version)
			if _, ok := unique[symbol]; ok {
				continue
			}
			for _, loc := range lib.Locators {
				yarnLibs[loc] = lib
				if len(deps) > 0 {
					dependsOn[loc] = deps
				}
			}
			unique[symbol] = struct{}{}
		}
	}

	libs, deps = parseResults(yarnLibs, dependsOn)
	return libs, deps, nil
}
