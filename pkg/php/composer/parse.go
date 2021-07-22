package composer

import (
	"bufio"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type lockFile struct {
	Packages []packageInfo
}
type packageInfo struct {
	Name    string
	Version string
}

func Parse(r io.Reader) ([]types.Library, error) {
	var lockFile lockFile
	decoder := json.NewDecoder(r)
	err := decoder.Decode(&lockFile)
	if err != nil {
		return nil, xerrors.Errorf("decode error: %w", err)
	}

	var libs []types.Library
	for _, pkg := range lockFile.Packages {
		libs = append(libs, types.Library{
			Name:    pkg.Name,
			Version: pkg.Version,
		})
	}
	return libs, nil
}

func ParseWordPress(r io.Reader) ([]types.Library, error) {
	var libs []types.Library
	// If wordpress file, open file and
	// find line with content
	// $wp_version = '<WORDPRESS_VERSION>';
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "$wp_version") {
			continue
		}
		wpVersionRegex, _ := regexp.Compile("'(.*?)'")
		version := strings.Trim(wpVersionRegex.FindString(line), "'")
		libs = append(libs, types.Library{
			Name:    "wordpress",
			Version: version,
			License: "",
		})
	}
	return libs, nil
}
