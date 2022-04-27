package bundler

import (
	"bufio"
	"io"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

type rubyParser struct {
	types.DefaultParser
}

func NewParser() *rubyParser {
	return &rubyParser{}
}

func (p *rubyParser) Parse(r io.Reader) ([]types.Library, []types.Dependency, error) {
	var libs []types.Library
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if countLeadingSpace(line) == 4 {
			line = strings.TrimSpace(line)
			s := strings.Fields(line)
			if len(s) != 2 {
				continue
			}
			libs = append(libs, types.Library{
				Name:    s[0],
				Version: strings.Trim(s[1], "()"),
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, xerrors.Errorf("scan error: %w", err)
	}
	return libs, nil, nil
}

func countLeadingSpace(line string) int {
	i := 0
	for _, runeValue := range line {
		if runeValue == ' ' {
			i++
		} else {
			break
		}
	}
	return i
}
