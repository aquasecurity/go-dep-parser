package packagejson

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
	"golang.org/x/xerrors"
)

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	License              any               `json:"license"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	Workspaces           []string          `json:"workspaces"`
}

type Package struct {
	types.Library
	Dependencies         map[string]string
	OptionalDependencies map[string]string
	DevDependencies      map[string]string
	Workspaces           []string
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r io.Reader) (Package, error) {
	var pkgJSON packageJSON
	if err := json.NewDecoder(r).Decode(&pkgJSON); err != nil {
		return Package{}, xerrors.Errorf("JSON decode error: %w", err)
	}

	var id string
	// Name and version fields are optional
	// https://docs.npmjs.com/cli/v9/configuring-npm/package-json#name
	if pkgJSON.Name != "" && pkgJSON.Version != "" {
		id = utils.PackageID(pkgJSON.Name, pkgJSON.Version)
	}

	return Package{
		Library: types.Library{
			ID:       id,
			Name:     pkgJSON.Name,
			Version:  pkgJSON.Version,
			Licenses: parseLicense(pkgJSON.License),
		},
		Dependencies:         pkgJSON.Dependencies,
		OptionalDependencies: pkgJSON.OptionalDependencies,
		DevDependencies:      pkgJSON.DevDependencies,
		Workspaces:           pkgJSON.Workspaces,
	}, nil
}

func parseLicense(val interface{}) types.Licenses {
	var license string
	// the license isn't always a string, check for legacy struct if not string
	switch v := val.(type) {
	case string:
		license = v
	case map[string]interface{}:
		if l, ok := v["type"]; ok {
			license = l.(string)
		}
	}

	// If the license is missing, it may be stored in the `LICENSE` file.
	if license == "" {
		return types.LicensesFromString("LICENSE", types.LicenseTypeFile)
	}

	// The license field can refer to a file:
	// https://docs.npmjs.com/cli/v9/configuring-npm/package-json#license
	var licenseFileName string
	if strings.HasPrefix(license, "LicenseRef-") {
		// LicenseRef-<filename>
		licenseFileName = strings.Split(license, "-")[1]
	} else if strings.HasPrefix(license, "SEE LICENSE IN ") {
		// SEE LICENSE IN <filename>
		parts := strings.Split(license, " ")
		licenseFileName = parts[len(parts)-1]
	}

	if licenseFileName != "" {
		return types.LicensesFromString(licenseFileName, types.LicenseTypeFile)
	}

	return types.LicensesFromString(license, types.LicenseTypeName)
}
