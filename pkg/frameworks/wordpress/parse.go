package wordpress

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

var (
	wpVersionRegex = regexp.MustCompile(`(\$wp_version\s*=\s*['"])(.*)(['"]\s*;)`)
	commentRegex   = regexp.MustCompile(`(/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/)|(//.*)`)
)

func Parse(r io.Reader) (lib types.Library, err error) {

	// If wordpress file, open file and
	// find line with content
	// $wp_version = '<WORDPRESS_VERSION>';

	var version string
	isComment := false
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "/*") {
			continue
		}
		if isComment && strings.HasSuffix(line, "*/") {
			isComment = false
			continue
		}

		// It might include $wp_version_something
		if !strings.HasPrefix(line, "$wp_version") {
			continue
		}

		ss := strings.Split(line, "=")
		if len(ss) != 2 || strings.TrimSpace(ss[0]) != "$wp_version" {
			continue
		}
		end := strings.Index(ss[1], ";")
		if end == -1 {
			continue
		}

		version = strings.Trim(strings.TrimSpace(ss[1][0:end]), `'"`)
		break
	}
	if err := scanner.Err(); err != nil || version == "" {
		return types.Library{}, xerrors.New("version.php could not be parsed")
	}

	return types.Library{
		Name:    "wordpress",
		Version: version,
		License: "",
	}, nil
}
