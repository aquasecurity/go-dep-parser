package packaging

import (
	"bufio"
	"io"
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
	if err != nil && err != io.EOF {
		return nil, nil, xerrors.Errorf("read MIME error: %w", err)
	}

	license := h.Get("License-Expression")
	if license == "" {
		license = h.Get("License")
	}
	if license == "" {
		for _, classifier := range h.Values("Classifier") {
			if strings.HasPrefix(classifier, "License ::") {
				if values := strings.Split(classifier, " :: "); len(values) > 1 {
					license = values[len(values)-1]
					break
				}
			}
		}
	}

	return []types.Library{
		{
			Name:        h.Get("Name"),
			Version:     h.Get("Version"),
			License:     license,
			LicenseFile: h.Get("License-File"),
		},
	}, nil, nil
}
