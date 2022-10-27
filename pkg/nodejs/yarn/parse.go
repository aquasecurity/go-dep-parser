package yarn

import (
	"bufio"
	"regexp"
	"strings"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
	"github.com/samber/lo"
	"golang.org/x/xerrors"
)

var (
	yarnLocatorRegexp      = regexp.MustCompile(`\\?"?(?P<package>.+?)@(?:(?P<protocol>.+?):)?(?P<version>.+?)\\?"?:?$`)
	yarnVersionRegexp      = regexp.MustCompile(`\s+"?version:?"?\s+"?(?P<version>[^"]+)"?`)
	yarnDependenciesRegexp = regexp.MustCompile(`\s+"?dependencies:?"?`)
	yarnDependencyRegexp   = regexp.MustCompile(`\s{4,}"?(?P<package>.+?)"?:?\s"?(?P<version>[^"]+)"?`)
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
	locs = lo.FlatMap(locsSplit, func(loc string, _ int) []string {
		_, _, version, _ := parseLocator(loc)
		ls := []string{utils.PackageID(packagename, version)}
		if protocol != "" {
			ls = append(ls, packagename+"@"+protocol+":"+version)
		}
		return ls
	})
	return
}

func getVersion(target string) (version string, err error) {
	capture := yarnVersionRegexp.FindStringSubmatch(target)
	if len(capture) < 2 {
		return "", xerrors.New("not version")
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

func (p *Parser) Parse(r dio.ReadSeekerAt) (libs []types.Library, deps []types.Dependency, err error) {
	scanner := bufio.NewScanner(r)
	unique := map[string]struct{}{}
	dependsOn := map[string][]Dependency{}
	yarnLibs := map[string]Library{}
	var lib Library
	var skipPackage bool
	var isInPackage bool
	var inDependenciesBlock bool
	var lineNumber int // It is used to save dependency location
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if len(line) < 1 {
			// save previous package
			if isInPackage {
				isInPackage = false
				inDependenciesBlock = false
				// fetch between version prefix and last double-quote
				symbol := utils.PackageID(lib.Name, lib.Version)
				if _, ok := unique[symbol]; ok {
					lib = Library{}
					continue
				}

				lib.Location.EndLine = lineNumber - 1

				for _, loc := range lib.Locators {
					yarnLibs[loc] = lib
				}
				unique[symbol] = struct{}{}

				lib = Library{}
			}
			continue
		}

		// parse dependency
		if inDependenciesBlock {
			if name, version, err := getDependency(line); err == nil {
				dep := Dependency{
					Locator: utils.PackageID(name, version),
					Name:    name,
				}
				lo.ForEach(lib.Locators, func(loc string, _ int) {
					if _, ok := dependsOn[loc]; !ok {
						dependsOn[loc] = []Dependency{}
					}
					dependsOn[loc] = append(dependsOn[loc], dep)
				})
				continue
			} else {
				inDependenciesBlock = false
			}
		}

		// parse version
		if version, err := getVersion(line); err == nil {
			if skipPackage {
				continue
			}

			if lib.Name == "" {
				return nil, nil, xerrors.New("Invalid yarn.lock format")
			}

			lib.Version = version
			continue
		}

		// skip __metadata block
		if skipPackage = strings.HasPrefix(line, "__metadata"); skipPackage {
			continue
		}

		// packagename line start 1 char
		if line[:1] != " " && line[:1] != "#" {
			var name string
			var protocol string
			var locs []string
			if name, protocol, locs, err = parsePackageLocators(line); err != nil || locs == nil {
				continue
			}
			if skipPackage = !validProtocol(protocol); skipPackage {
				continue
			}
			lib.Name = name
			lib.Locators = locs
			// use line number of dependency name for location
			lib.Location = types.Location{
				StartLine: lineNumber,
			}
			isInPackage = true
		}

		// start dependencies block
		if isInPackage && yarnDependenciesRegexp.MatchString(line) {
			inDependenciesBlock = true
			continue
		}
	}
	// scanner doesn't iterate last line
	for _, loc := range lib.Locators {
		lib.Location.EndLine = lineNumber
		yarnLibs[loc] = lib
	}

	libs, deps = parseResults(yarnLibs, dependsOn)
	return libs, deps, nil
}
