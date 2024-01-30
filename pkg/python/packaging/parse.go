package packaging

import (
	"bufio"
	"errors"
	"io"
	"net/textproto"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
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
	if e := textproto.ProtocolError(""); errors.As(err, &e) {
		// A MIME header may contain bytes in the key or value outside the set allowed by RFC 7230.
		// cf. https://cs.opensource.google/go/go/+/a6642e67e16b9d769a0c08e486ba08408064df19
		// However, our required key/value could have been correctly parsed,
		// so we continue with the subsequent process.
		log.Logger.Debugf("MIME protocol error: %s", err)
	} else if err != nil && err != io.EOF {
		return nil, nil, xerrors.Errorf("read MIME error: %w", err)
	}

	name, version := h.Get("name"), h.Get("version")
	if name == "" || version == "" {
		return nil, nil, xerrors.New("name or version is empty")
	}

	// "License-Expression" takes precedence as "License" is deprecated.
	// cf. https://peps.python.org/pep-0639/#deprecate-license-field
	var licenses types.Licenses
	if l := h.Get("License-Expression"); l != "" {
		licenses = types.LicensesFromString(l, types.NameLicenseType)
	} else if l := h.Get("License"); l != "" {
		// The license field can contain information about different licenses, license exceptions , etc.:
		// https://packaging.python.org/en/latest/specifications/core-metadata/#license,
		// but it is impossible to define a delimiter to separate them.
		// Mark them, so we don't have to separate them later.
		licenses = types.LicensesFromString(l, types.NonSeparableTextLicenseType)
	} else {
		// license classifiers are deprecated:
		// https://peps.python.org/pep-0639/#deprecate-license-classifiers
		for _, classifier := range h.Values("Classifier") {
			if strings.HasPrefix(classifier, "License :: ") {
				values := strings.Split(classifier, " :: ")
				// there can be several classifiers with licenses
				licenses = append(licenses, types.LicensesFromString(values[len(values)-1], types.NameLicenseType)...)
			}
		}
	}
	if len(licenses) == 0 && h.Get("License-File") != "" {
		licenses = types.LicensesFromStringSlice(h.Values("License-File"), types.FileLicenseType)
	}

	return []types.Library{
		{
			Name:     name,
			Version:  version,
			Licenses: licenses,
		},
	}, nil, nil
}
