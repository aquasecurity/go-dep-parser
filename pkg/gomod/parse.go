package gomod

import (
	"io"
	"io/ioutil"

	"golang.org/x/mod/modfile"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

// Parse parses go.mod file
func Parse(r io.Reader) ([]types.Library, error) {
	var libs []types.Library

	fileContent, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	parsedContent, err := modfile.Parse("dummyFileName", fileContent, nil)
	if err != nil {
		return nil, err
	}

	// if there is no replace section, just use the require section
	if 0 == len(parsedContent.Replace) {
		for _, require := range parsedContent.Require {
			libs = append(libs, types.Library{
				Name:    require.Mod.Path,
				Version: require.Mod.Version,
			})
		}
	} else {
		// first, add all require section to a map
		mapOfLibs := make(map[string]string)
		for _, require := range parsedContent.Require {
			mapOfLibs[require.Mod.Path] = require.Mod.Version
		}

		// remove key added via require section and add key, value from replace section
		for _, replace := range parsedContent.Replace {
			delete(mapOfLibs, replace.Old.Path)
			mapOfLibs[replace.New.Path] = replace.New.Version
		}

		// convert map to a slice
		for key, val := range mapOfLibs {
			libs = append(libs, types.Library{
				Name:    key,
				Version: val,
			})
		}
	}

	return libs, nil
}
