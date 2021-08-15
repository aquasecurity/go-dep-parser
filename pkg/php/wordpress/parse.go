package wordpress

import (
	"io"
	"regexp"

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

var (
	wpVersionRegex = regexp.MustCompile(`(\$wp_version\s*=\s*['"])(.*)(['"]\s*;)`)
	commentRegex   = regexp.MustCompile(`(/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/)|(//.*)`)
)

func Parse(r io.Reader) (lib types.Library, err error) {

	// If wordpress file, open file and
	// find line with content
	// $wp_version = '<WORDPRESS_VERSION>';
	content, err := readAll(r)
	if err != nil {
		return lib, xerrors.Errorf("decode error: %w", err)
	}

	contentStr := string(commentRegex.ReplaceAll(content, []byte{}))

	matches := wpVersionRegex.FindAllStringSubmatch(contentStr, 3)

	if len(matches) != 1 {
		return lib, xerrors.New("version.php could not be parsed")
	}

	return types.Library{
		Name:    "wordpress",
		Version: matches[0][2],
		License: "",
	}, nil
}

func readAll(r io.Reader) ([]byte, error) {
	b := make([]byte, 0, 512)
	for {
		if len(b) == cap(b) {
			// Add more capacity (let append pick how much).
			b = append(b, 0)[:len(b)]
		}
		n, err := r.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return b, err
		}
	}
}
