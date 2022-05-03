package packaging

import (
	"archive/zip"
	"bufio"
	"io"
	"net/textproto"
	"os"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

type Parser struct {
	size       int64
	filePath   string
	isRequired func(filePath string, _ os.FileInfo) bool
}

func NewParser(filePath string, size int64, isRequired func(filePath string, _ os.FileInfo) bool) types.Parser {
	return &Parser{
		size:       size,
		filePath:   filePath,
		isRequired: isRequired,
	}
}

// Parse parses egg and wheel metadata.
// e.g. .egg-info/PKG-INFO and dist-info/METADATA
func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var zr io.ReadCloser = r.(io.ReadCloser)

	// .egg file is zip format and PKG-INFO needs to be extracted from the zip file.
	if strings.HasSuffix(p.filePath, ".egg") {
		pkginfoInZip, err := p.analyzeEggZip(r.(io.ReaderAt), p.size)
		if err != nil {
			return nil, nil, xerrors.Errorf("egg analysis error: %w", err)
		}
		if pkginfoInZip == nil { // Egg archive may not contain required files, then we will get nil. Skip this archives
			return nil, nil, nil
		}

		defer pkginfoInZip.Close()

		zr = pkginfoInZip
	}

	rd := textproto.NewReader(bufio.NewReader(zr))
	h, err := rd.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, nil, xerrors.Errorf("read MIME error: %w", err)
	}

	return []types.Library{{
		Name:    h.Get("Name"),
		Version: h.Get("Version"),
		License: h.Get("License"),
	}}, nil, nil
}

func (p *Parser) analyzeEggZip(r io.ReaderAt, size int64) (io.ReadCloser, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, xerrors.Errorf("zip reader error: %w", err)
	}

	for _, file := range zr.File {
		if !p.isRequired(file.Name, nil) {
			continue
		}
		return open(file)
	}

	return nil, nil
}

func open(file *zip.File) (io.ReadCloser, error) {
	f, err := file.Open()
	if err != nil {
		return nil, err
	}
	return f, nil
}
