package pnpm

import (
	"io"
	"io/ioutil"
	"regexp"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"
)

var (
	pnpmVersionRegexp = regexp.MustCompile(`\d+(\.\d+)+`)
)

const (
	packageDirective = "packages"
)

func Parse(r io.Reader) ([]types.Library, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, xerrors.Errorf("unable to read the yaml file: %w", err)
	}

	dependencies := make(map[interface{}]interface{})

	err = yaml.Unmarshal(b, dependencies)
	if err != nil {
		return nil, xerrors.Errorf("decode error: %w", err)
	}

	libs, err := parse(dependencies)
	if err != nil {
		return nil, err
	}
	if len(libs) == 0 {
		return nil, xerrors.New("dont find packages")
	}

	return unique(libs), nil
}

func parse(dependencies map[interface{}]interface{}) ([]types.Library, error) {
	if _, ok := dependencies[packageDirective]; !ok {
		return nil, xerrors.New("there is no dependencies list")
	}

	listPackages := dependencies[packageDirective].(map[string]interface{})
	if len(listPackages) == 0 {
		return nil, xerrors.New("empty dependencies list")
	}

	var libs []types.Library

	for packageInfo, packAdditionalInfo := range listPackages {
		version, name := takePackageInfo(packageInfo)
		curPckg := packAdditionalInfo.(map[string]interface{})
		if val, ok := curPckg["version"]; ok {
			version = val.(string)
		}
		if val, ok := curPckg["name"]; ok {
			name = val.(string)
		}

		if len(version) == 0 || len(name) == 0 {
			return nil, xerrors.Errorf("could not parse: %s", packageInfo)
		}

		libs = append(libs, types.Library{
			Name:    name,
			Version: version,
		})
	}

	return libs, nil
}

func unique(libs []types.Library) []types.Library {
	var uniqLibs []types.Library
	unique := map[types.Library]struct{}{}
	for _, lib := range libs {
		if _, ok := unique[lib]; !ok {
			unique[lib] = struct{}{}
			uniqLibs = append(uniqLibs, lib)
		}
	}
	return uniqLibs
}

func takePackageInfo(packageInfo string) (string, string) {
	arrIndexes := pnpmVersionRegexp.FindStringSubmatchIndex(packageInfo)
	if len(arrIndexes) == 0 {
		return "", ""
	}

	version := packageInfo[arrIndexes[0]:arrIndexes[len(arrIndexes)-1]]
	name := packageInfo[1 : arrIndexes[0]-1]

	return version, name
}
