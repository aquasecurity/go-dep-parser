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

	// "License-Expression" takes precedence as "License" is deprecated.
	// cf. https://peps.python.org/pep-0639/#deprecate-license-field
	var license string
	if l := h.Get("License-Expression"); l != "" {
		license = l
	} else if l := h.Get("License"); l != "" {
		// The license field can contain information about different licenses, license exceptions , etc.:
		// https://packaging.python.org/en/latest/specifications/core-metadata/#license,
		// but it is impossible to define a delimiter to separate them.
		// Mark them, so we don't have to separate them later.
		license = types.NonSeparableLicensePrefix + l
	} else {
		var licenses []string
		// license classifiers are deprecated:
		// https://peps.python.org/pep-0639/#deprecate-license-classifiers
		for _, classifier := range h.Values("Classifier") {
			if strings.HasPrefix(classifier, "License :: ") {
				values := strings.Split(classifier, " :: ")
				// there can be several classifiers with licenses
				licenses = append(licenses, values[len(values)-1])
			}
		}
		license = strings.Join(licenses, ", ")
	}
	if license == "" && h.Get("License-File") != "" {
		var licenseFiles []string
		for _, licenseFile := range h.Values("License-File") {
			// there can be several license files
			licenseFiles = append(licenseFiles, "file://"+licenseFile)
		}
		license = strings.Join(licenseFiles, ", ")
	}

	return []types.Library{
		{
			Name:    h.Get("Name"),
			Version: h.Get("Version"),
			License: license,
		},
	}, nil, nil
}
