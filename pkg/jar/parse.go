package jar

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

const (
	baseURL   = "http://search.maven.org/solrsearch/select"
	idQuery   = `g:"%s"+AND+a:"%s"`
	sha1Query = `1:"%s"`
)

type conf struct {
	baseURL string
}

type Option func(*conf)

func WithURL(url string) Option {
	return func(c *conf) {
		c.baseURL = url
	}
}

func Parse(r io.Reader, opts ...Option) ([]types.Library, error) {
	c := conf{baseURL: baseURL}
	for _, opt := range opts {
		opt(&c)
	}

	return parseArtifact(c, ioutil.NopCloser(r))
}

func parseArtifact(c conf, r io.ReadCloser) ([]types.Library, error) {
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
	var props properties
	var m manifest
	for _, fileInJar := range zr.File {
		switch {
		case filepath.Base(fileInJar.Name) == "pom.properties":
			props, err = parsePomProperties(fileInJar)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse %s: %w", fileInJar.Name, err)
			}
		case filepath.Base(fileInJar.Name) == "MANIFEST.MF":
			m, err = parseManifest(fileInJar)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse MANIFEST.INF: %w", err)
			}
		case isArtifact(fileInJar.Name):
			fr, err := fileInJar.Open()
			if err != nil {
				return nil, xerrors.Errorf("unable to open %s: %w", fileInJar.Name, err)
			}

			// parse jar/war/ear recursively
			innerLibs, err := parseArtifact(c, fr)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse %s: %w", fileInJar.Name, err)
			}
			libs = append(libs, innerLibs...)
		}
	}

	// If pom.properties is found, it should be preferred than MANIFEST.MF.
	if props.valid() {
		return append(libs, props.library()), nil
	}

	manifestProps := m.properties()
	if !manifestProps.valid() {
		return libs, nil
	}

	// Even if MANIFEST.MF is found, the groupId and artifactId might not be valid.
	// We have to make sure that the artifact exists actually.
	if ok, _ := exists(c, manifestProps); ok {
		// If groupId and artifactId are valid, they will be returned.
		return append(libs, manifestProps.library()), nil
	}

	// If groupId and artifactId are not found, call Maven Central's search API with SHA-1 digest.
	p, err := searchSHA1(c, b)
	if err == nil {
		libs = append(libs, p.library())
	}

	return libs, nil
}

func isArtifact(name string) bool {
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

func parseManifest(f *zip.File) (manifest, error) {
	file, err := f.Open()
	if err != nil {
		return manifest{}, xerrors.Errorf("unable to open MANIFEST.INF: %w", err)
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
		return manifest{}, xerrors.Errorf("scan error: %w", err)
	}
	return m, nil
}

type apiResponse struct {
	Response struct {
		NumFound int `json:"numFound"`
		Docs     []struct {
			ID         string `json:"id"`
			GroupID    string `json:"g"`
			ArtifactID string `json:"a"`
			Version    string `json:"v"`
			P          string `json:"p"`
		} `json:"docs"`
	} `json:"response"`
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

func exists(c conf, p properties) (bool, error) {
	req, err := http.NewRequest("GET", c.baseURL, nil)
	if err != nil {
		return false, xerrors.Errorf("unable to initialize HTTP client: %w", err)
	}

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf(idQuery, p.groupID, p.artifactID))
	q.Set("rows", "1")
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, xerrors.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	var res apiResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false, xerrors.Errorf("json decode error: %w", err)
	}
	return res.Response.NumFound > 0, nil
}

func searchSHA1(c conf, data []byte) (properties, error) {
	h := sha1.New()
	_, err := h.Write(data)
	if err != nil {
		return properties{}, xerrors.Errorf("unable to calculate SHA-1: %w", err)
	}
	digest := hex.EncodeToString(h.Sum(nil))

	req, err := http.NewRequest("GET", c.baseURL, nil)
	if err != nil {
		return properties{}, xerrors.Errorf("unable to initialize HTTP client: %w", err)
	}

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf(sha1Query, digest))
	q.Set("rows", "1")
	q.Set("wt", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return properties{}, xerrors.Errorf("sha1 search error: %w", err)
	}
	defer resp.Body.Close()

	var res apiResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return properties{}, xerrors.Errorf("json decode error: %w", err)
	}

	if len(res.Response.Docs) == 0 {
		return properties{}, xerrors.Errorf("no artifact found: %s", digest)
	}

	// Some artifacts might have the same SHA-1 digests.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	docs := res.Response.Docs
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].ID < docs[j].ID
	})
	d := docs[0]

	return properties{
		groupID:    d.GroupID,
		artifactID: d.ArtifactID,
		version:    d.Version,
	}, nil
}
