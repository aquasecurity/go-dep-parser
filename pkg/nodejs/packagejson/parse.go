package packagejson

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
	"golang.org/x/xerrors"
)

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	License              interface{}       `json:"license"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func (p packageJSON) hasContent() bool {
	return parseLicense(p.License) != "" || p.Dependencies != nil || p.OptionalDependencies != nil
}

type Package struct {
	types.Library
	Dependencies         map[string]string
	OptionalDependencies map[string]string
}

type Now func() time.Time

type Option func(p *Parser)

func WithNow(now Now) Option {
	return func(p *Parser) {
		p.now = now
	}
}

type Parser struct {
	now Now
}

func NewParser(opts ...Option) *Parser {
	p := &Parser{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *Parser) Parse(r io.Reader) (Package, error) {
	var pkgJSON packageJSON
	if err := json.NewDecoder(r).Decode(&pkgJSON); err != nil {
		return Package{}, xerrors.Errorf("JSON decode error: %w", err)
	}

	if pkgJSON.Name == "" && pkgJSON.Version == "" && !pkgJSON.hasContent() {
		return Package{}, nil
	}

	name := pkgJSON.Name
	if name == "" {
		name = fmt.Sprintf("mypackage-%s", p.now().UTC().Format(time.RFC3339))
	}

	return Package{
		Library: types.Library{
			ID:      utils.PackageID(name, pkgJSON.Version),
			Name:    name,
			Version: pkgJSON.Version,
			License: parseLicense(pkgJSON.License),
		},
		Dependencies:         pkgJSON.Dependencies,
		OptionalDependencies: pkgJSON.OptionalDependencies,
	}, nil
}

func parseLicense(val interface{}) string {
	// the license isn't always a string, check for legacy struct if not string
	switch v := val.(type) {
	case string:
		return v
	case map[string]interface{}:
		if license, ok := v["type"]; ok {
			return license.(string)
		}
	}
	return ""
}
