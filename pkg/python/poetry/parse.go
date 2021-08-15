package poetry

import (
	"io"

	"github.com/BurntSushi/toml"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type Lockfile struct {
	Packages []struct {
		Category       string `toml:"category"`
		Description    string `toml:"description"`
		Marker         string `toml:"marker,omitempty"`
		Name           string `toml:"name"`
		Optional       bool   `toml:"optional"`
		PythonVersions string `toml:"python-versions"`
		Version        string `toml:"version"`
		Dependencies   interface{}
		Metadata       interface{}
	} `toml:"package"`
}

func Parse(r io.Reader) ([]types.Library, error) {
	var lockfile Lockfile
	if _, err := toml.DecodeReader(r, &lockfile); err != nil {
		return nil, xerrors.Errorf("decode error: %w", err)
	}

	var libs []types.Library
	for _, pkg := range lockfile.Packages {
		libs = append(libs, types.Library{
			Name:    pkg.Name,
			Version: pkg.Version,
		})
	}
	return libs, nil
}
