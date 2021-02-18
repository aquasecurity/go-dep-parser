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
		tmp[s[0]] = strings.TrimSuffix(strings.TrimPrefix(s[1], "v"), "/go.mod")
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
