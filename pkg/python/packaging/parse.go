package packaging

import (
	"bufio"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"net/textproto"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

// Parse parses egg and wheel metadata.
// e.g. .egg-info/PKG-INFO and dist-info/METADATA
func (*Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	rd := textproto.NewReader(bufio.NewReader(r))
	h, err := rd.ReadMIMEHeader()
	name, version := h.Get("name"), h.Get("version")
	if err != nil {
		if name == "" || version == "" {
			// Some unnecessary headers for this case may contain bytes in the
			// key or value outside the set allowed by RFC 7230
			// In this case we get error:
			// cf. https://cs.opensource.google/go/go/+/a6642e67e16b9d769a0c08e486ba08408064df19
			// If `name` and `version` are found, we don't need to stop
			return nil, nil, xerrors.Errorf("read MIME error: %w", err)
		}
		log.Logger.Debugf("Package 'name' and 'version' were found, but a MIME reading error occurs: %s", err)
	}

	// "License-Expression" takes precedence as "License" is deprecated.
	// cf. https://peps.python.org/pep-0639/#deprecate-license-field
	var license string
	if l := h.Get("License-Expression"); l != "" {
		license = l
	} else if l := h.Get("License"); l != "" {
		license = l
	} else {
		for _, classifier := range h.Values("Classifier") {
			if strings.HasPrefix(classifier, "License :: ") {
				values := strings.Split(classifier, " :: ")
				license = values[len(values)-1]
				break
			}
		}
	}
	if license == "" && h.Get("License-File") != "" {
		license = "file://" + h.Get("License-File")
	}

	return []types.Library{
		{
			Name:    name,
			Version: version,
			License: license,
		},
	}, nil, nil
}
