package python

import (
	"bufio"
	"fmt"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"io"
	"strings"
)

func Parse(r io.Reader) ([]types.Library, error) {
	scanner := bufio.NewScanner(r)
	var libs []types.Library
	for scanner.Scan() {
		line := scanner.Text()
		s := strings.Split(line, "==")
		if len(s) != 2 {
			continue
		}
		libs = append(libs, types.Library{
			Name:    s[0],
			Version: s[1],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}
	return libs, nil
}
