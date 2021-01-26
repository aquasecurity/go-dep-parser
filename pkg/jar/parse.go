package jar

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func Parse(r io.Reader) ([]types.Library, error) {
	return parseJar(ioutil.NopCloser(r))
}

func parseJar(r io.ReadCloser) ([]types.Library, error) {
	defer r.Close()

	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, xerrors.Errorf("unable to read the jar file: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, xerrors.Errorf("zip error: %w", err)
	}

	var libs []types.Library
	var pomProps, manifestProps properties
	for _, fileInJar := range zr.File {
		switch {
		case filepath.Base(fileInJar.Name) == "pom.properties":
			pomProps, err = parsePomProperties(fileInJar)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse %s: %w", fileInJar.Name, err)
			}
		case filepath.Base(fileInJar.Name) == "MANIFEST.MF":
			manifestProps, err = parseManifest(fileInJar)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse MANIFEST.INF: %w", err)
			}
		case isJavaArchive(fileInJar.Name):
			fr, err := fileInJar.Open()
			if err != nil {
				return nil, xerrors.Errorf("unable to open %s: %w", fileInJar.Name, err)
			}

			// parse jar/war/ear recursively
			innerLibs, err := parseJar(fr)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse %s: %w", fileInJar.Name, err)
			}
			libs = append(libs, innerLibs...)
		}
	}

	// If pom.properties is found, it should be preferred than MANIFEST.MF
	if pomProps.valid() {
		libs = append(libs, pomProps.library())
	} else if manifestProps.valid() {
		libs = append(libs, manifestProps.library())
	}

	return libs, nil
}

func isJavaArchive(name string) bool {
	ext := filepath.Ext(name)
	if ext == ".jar" || ext == ".ear" || ext == ".war" {
		return true
	}
	return false
}

type properties struct {
	groupID    string
	artifactID string
	version    string
}

func parsePomProperties(f *zip.File) (properties, error) {
	file, err := f.Open()
	if err != nil {
		return properties{}, xerrors.Errorf("unable to open pom.properties: %w", err)
	}
	defer file.Close()

	var p properties
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "groupId="):
			p.groupID = strings.TrimPrefix(line, "groupId=")
		case strings.HasPrefix(line, "artifactId="):
			p.artifactID = strings.TrimPrefix(line, "artifactId=")
		case strings.HasPrefix(line, "version="):
			p.version = strings.TrimPrefix(line, "version=")
		}
	}

	if err = scanner.Err(); err != nil {
		return properties{}, xerrors.Errorf("scan error: %w", err)
	}
	return p, nil
}

func (p properties) library() types.Library {
	return types.Library{
		Name:    fmt.Sprintf("%s:%s", p.groupID, p.artifactID),
		Version: p.version,
	}
}

func (p properties) valid() bool {
	return p.groupID != "" && p.artifactID != "" && p.version != ""
}

type manifest struct {
	implementationVersion  string
	implementationTitle    string
	implementationVendorId string
	specificationTitle     string
	specificationVersion   string
	bundleName             string
	bundleVersion          string
	bundleSymbolicName     string
}

func parseManifest(f *zip.File) (properties, error) {
	file, err := f.Open()
	if err != nil {
		return properties{}, xerrors.Errorf("unable to open MANIFEST.INF: %w", err)
	}
	defer file.Close()

	var m manifest
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// It is not determined which fields are present in each application.
		// In some cases, none of them are included, in which case they cannot be detected.
		switch {
		case strings.HasPrefix(line, "Implementation-Version:"):
			m.implementationVersion = strings.TrimPrefix(line, "Implementation-Version:")
		case strings.HasPrefix(line, "Implementation-Title:"):
			m.implementationTitle = strings.TrimPrefix(line, "Implementation-Title:")
		case strings.HasPrefix(line, "Implementation-Vendor-Id:"):
			m.implementationVendorId = strings.TrimPrefix(line, "Implementation-Vendor-Id:")
		case strings.HasPrefix(line, "Specification-Version:"):
			m.specificationVersion = strings.TrimPrefix(line, "Specification-Version:")
		case strings.HasPrefix(line, "Specification-Title:"):
			m.specificationTitle = strings.TrimPrefix(line, "Specification-Title:")
		case strings.HasPrefix(line, "Bundle-Version:"):
			m.bundleVersion = strings.TrimPrefix(line, "Bundle-Version:")
		case strings.HasPrefix(line, "Bundle-Name:"):
			m.bundleName = strings.TrimPrefix(line, "Bundle-Name:")
		case strings.HasPrefix(line, "Bundle-SymbolicName:"):
			m.bundleSymbolicName = strings.TrimPrefix(line, "Bundle-SymbolicName:")
		}
	}

	if err = scanner.Err(); err != nil {
		return properties{}, xerrors.Errorf("scan error: %w", err)
	}
	return m.properties(), nil
}

func (m manifest) properties() properties {
	groupID, err := m.determineGroupID()
	if err != nil {
		return properties{}
	}

	artifactID, err := m.determineArtifactID()
	if err != nil {
		return properties{}
	}

	version, err := m.determineVersion()
	if err != nil {
		return properties{}
	}

	return properties{
		groupID:    groupID,
		artifactID: artifactID,
		version:    version,
	}
}

func (m manifest) determineGroupID() (string, error) {
	var groupID string
	switch {
	case m.implementationVendorId != "":
		groupID = m.implementationVendorId
	case m.bundleSymbolicName != "":
		groupID = m.bundleSymbolicName

		// e.g. "com.fasterxml.jackson.core.jackson-databind" => "com.fasterxml.jackson.core"
		idx := strings.LastIndex(m.bundleSymbolicName, ".")
		if idx > 0 {
			groupID = m.bundleSymbolicName[:idx]
		}
	default:
		return "", xerrors.New("no groupID found")
	}
	return strings.TrimSpace(groupID), nil
}

func (m manifest) determineArtifactID() (string, error) {
	var artifactID string
	switch {
	case m.implementationTitle != "":
		artifactID = m.implementationTitle
	case m.specificationTitle != "":
		artifactID = m.specificationTitle
	case m.bundleName != "":
		artifactID = m.bundleName
	default:
		return "", xerrors.New("no artifactID found")
	}
	return strings.TrimSpace(artifactID), nil
}

func (m manifest) determineVersion() (string, error) {
	var version string
	switch {
	case m.implementationVersion != "":
		version = m.implementationVersion
	case m.specificationVersion != "":
		version = m.specificationVersion
	case m.bundleVersion != "":
		version = m.bundleVersion
	default:
		return "", xerrors.New("no version found")
	}
	return strings.TrimSpace(version), nil
}
