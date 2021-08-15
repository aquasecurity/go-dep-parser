package gemspec

import (
	"bufio"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

var (
	bwQuotes = regexp.MustCompile(`['|"](.*?)['|"]`)
)

func Parse(r io.Reader, filePath string) (types.Library, error) {
	scanner := bufio.NewScanner(r)
	var gemName string
	var gemVersion string
	var licenses []string
	for scanner.Scan() {
		line := scanner.Text()
		// check if the file is binary or not, if binary return
		if !utf8.ValidString(line) {
			return types.Library{}, nil
		}
		quotesList := bwQuotes.FindStringSubmatch(line)
		if len(quotesList) > 1 {
			line = strings.TrimSpace(line)
			if gemName == "" && strings.HasPrefix(line, "s.name") {
				gemName = quotesList[1]
			} else if gemVersion == "" && strings.HasPrefix(line, "s.version") {
				gemVersion = quotesList[1]
			} else if strings.HasPrefix(line, "s.licenses") {
				licenseList := bwQuotes.FindAllStringSubmatch(line, -1)
				for _, license := range licenseList {
					licenses = append(licenses, strings.Replace(license[1], " ", "", -1))
				}
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return types.Library{}, xerrors.Errorf("Scan error: %w", err)
	}

	if gemName == "" || gemVersion == "" {
		return types.Library{}, nil
	}

	return types.Library{
		Name:    gemName,
		Version: gemVersion,
		License: strings.Join(licenses, ","),
	}, nil
}
