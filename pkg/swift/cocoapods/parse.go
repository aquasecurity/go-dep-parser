package cocoapods

import (
	"fmt"
	"reflect"
	"strings"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

const idFormat = "%s/%s"

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

type lockFile struct {
	Pods []interface{} `yaml:"PODS"` // pod can be string or map[string]interface{}
}

func (Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	lock := &lockFile{}
	decoder := yaml.NewDecoder(r)
	if err := decoder.Decode(&lock); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode cocoapods lock file: %s", err.Error())
	}

	parsedDeps := map[string]types.Library{} // dependency name => Library
	directDeps := map[string][]string{}      // dependency name => slice of child dependency names
	for _, pod := range lock.Pods {
		switch reflect.ValueOf(pod).Kind() {
		case reflect.String: // dependency with version number
			lib, err := parseDep(pod.(string), false)
			if err != nil {
				log.Logger.Debug(err)
				continue
			}
			parsedDeps[lib.Name] = lib
		case reflect.Map: // dependency with its direct dependencies
			for dep, childDeps := range pod.(map[string]interface{}) {
				lib, err := parseDep(dep, false)
				if err != nil {
					log.Logger.Debug(err)
					continue
				}
				parsedDeps[lib.Name] = lib

				if reflect.ValueOf(childDeps).Kind() != reflect.Slice {
					return nil, nil, xerrors.Errorf("Wrong value of cocoapods direct dependency: %q", childDeps)
				}

				for _, childDep := range childDeps.([]interface{}) {
					childDepName, _ := parseDep(childDep.(string), true)
					directDeps[lib.Name] = append(directDeps[lib.Name], childDepName.Name)
				}
			}
		}
	}

	var deps []types.Dependency
	for dep, childDeps := range directDeps {
		var dependsOn []string
		// find versions for direct dependencies
		for _, childDep := range childDeps {
			// mark this dep as indirect
			lib := parsedDeps[childDep]
			lib.Indirect = true
			parsedDeps[childDep] = lib

			dependsOn = append(dependsOn, fmt.Sprintf(idFormat, childDep, lib.Version))
		}
		deps = append(deps, types.Dependency{
			ID:        parsedDeps[dep].ID,
			DependsOn: dependsOn,
		})
	}

	return utils.UniqueLibraries(maps.Values(parsedDeps)), deps, nil
}

func parseDep(dep string, childDep bool) (types.Library, error) {
	// dep example:
	// 'AppCenter (4.2.0)'
	// direct dep examples:
	// 'AppCenter/Core'
	// 'AppCenter/Analytics (= 4.2.0)'
	// 'AppCenter/Analytics (-> 4.2.0)'
	ss := strings.Split(dep, " (")
	if childDep { // get only dependency name for child deps
		return types.Library{Name: ss[0]}, nil
	}
	if len(ss) != 2 {
		return types.Library{}, xerrors.Errorf("Unable to determine cocoapods dependency: %q", dep)
	}

	lib := types.Library{
		ID:      fmt.Sprintf(idFormat, ss[0], strings.TrimSuffix(ss[1], ")")),
		Name:    ss[0],
		Version: strings.TrimSuffix(ss[1], ")"),
	}

	return lib, nil
}
