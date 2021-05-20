package python

import (
	"bufio"
	"io"
	"strings"
	"unicode"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

const commentRune string = "#"

func Parse(r io.Reader) ([]types.Library, error) {
	scanner := bufio.NewScanner(r)
	var libs []types.Library
	for scanner.Scan() {
		line := scanner.Text()
		stripAllSpaces(&line)
		stripComments(&line)
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
		return nil, xerrors.Errorf("scan error: %w", err)
	}
	return libs, nil
}

func stripComments(line *string) {
	if pos := strings.IndexAny(*line, commentRune); pos >= 0 {
		*line = strings.TrimRightFunc((*line)[:pos], unicode.IsSpace)
	}
}

func stripAllSpaces(line *string) {
	*line = strings.ReplaceAll(*line, " ", "")
}
