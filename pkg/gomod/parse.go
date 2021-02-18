package gomod

import (
	"bufio"
	"io"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

// Parse parses a go.sum file
func Parse(r io.Reader) ([]types.Library, error) {
	var libs []types.Library
	tmp := make(map[string]string)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		s := strings.Fields(line)
		// go.sum records and sorts all non-major versions
		// with the latest version as last entry
		tmp[s[0]] = parseSemVer(s[1])
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	for k, v := range tmp {
		libs = append(libs, types.Library{
			Name:    k,
			Version: v,
		})
	}

	return libs, nil
}

// parseSemVer parses semver from go.sum
// ignoring pseudo-version
func parseSemVer(v string) string {
	v = strings.TrimPrefix(v, "v")
	vv := strings.Split(v, ".")
	vv[2] = strings.Join(vv[2:], ".")
	vv[2] = strings.TrimSuffix(vv[2], "/go.mod")

	return strings.Join(vv[:3], ".")
}
