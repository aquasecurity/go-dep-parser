package cargo

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type pkgPosition struct {
	start int
	end   int
}
type minPkg struct {
	name     string
	version  string
	position pkgPosition
}

func (pkg *minPkg) setEndPositionIfEmpty(n int) {
	if pkg.position.end == 0 {
		pkg.position.end = n
	}
}

type naivePkgParser struct {
	r io.Reader
}

var pkgDelimiterRegexp = regexp.MustCompile(`^\s*\[`)
var pkgNameRegexp = regexp.MustCompile(`^\s*name\s=`)
var pkgVersionRegexp = regexp.MustCompile(`^\s*version\s=`)
var emptyLineRegexp = regexp.MustCompile(`^\s*$`)

func (parser *naivePkgParser) parse() map[string]pkgPosition {
	var currentPkg minPkg = minPkg{}
	var idx = make(map[string]pkgPosition, 0)

	scanner := bufio.NewScanner(parser.r)
	lineNum := 1
	for scanner.Scan() {
		line := scanner.Text()
		if matched := pkgDelimiterRegexp.MatchString(line); matched {
			if currentPkg.name != "" {
				pkgId := utils.PackageID(currentPkg.name, currentPkg.version)
				currentPkg.setEndPositionIfEmpty(lineNum - 1)
				idx[pkgId] = currentPkg.position
			}
			currentPkg = minPkg{}
			currentPkg.position.start = lineNum

		} else if matched := pkgNameRegexp.MatchString(line); matched {
			currentPkg.name = propertyValue(line)
		} else if matched := pkgVersionRegexp.MatchString(line); matched {
			currentPkg.version = propertyValue(line)
		} else if matched := emptyLineRegexp.MatchString(line); matched {
			currentPkg.setEndPositionIfEmpty(lineNum - 1)
		}

		lineNum++
	}
	// add last item
	if currentPkg.name != "" {
		pkgId := fmt.Sprintf("%s@%s", currentPkg.name, currentPkg.version)
		currentPkg.setEndPositionIfEmpty(lineNum - 1)
		idx[pkgId] = currentPkg.position
	}
	return idx
}
func propertyValue(line string) string {
	parts := strings.Split(line, "=")
	if len(parts) == 2 {
		return strings.Trim(parts[1], ` "`)
	}
	return ""
}
