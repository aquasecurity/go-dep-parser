package jar

import (
	"archive/zip"
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"github.com/aquasecurity/go-dep-parser/pkg/java/jar/searchers"
	"github.com/aquasecurity/go-dep-parser/pkg/java/jar/searchers/db"
	"github.com/aquasecurity/go-dep-parser/pkg/java/jar/searchers/maven"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	jtypes "github.com/aquasecurity/go-dep-parser/pkg/java/jar/types"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

const (
	baseURL   = "https://search.maven.org/solrsearch/select"
	baseDBDir = "trivy/java-db"
)

var (
	jarFileRegEx = regexp.MustCompile(`^([a-zA-Z0-9\._-]*[^-*])-(\d\S*(?:-SNAPSHOT)?).jar$`)
)

type Parser struct {
	rootFilePath string
	offline      bool
	size         int64

	mavenSearcher maven.Searcher
	dbSearcher    db.Searcher
}

type Option func(*Parser)

func WithURL(url string) Option {
	return func(p *Parser) {
		p.mavenSearcher.BaseURL = url
	}
}

func WithFilePath(filePath string) Option {
	return func(p *Parser) {
		p.rootFilePath = filePath
	}
}

func WithHTTPClient(client *http.Client) Option {
	return func(p *Parser) {
		p.mavenSearcher.HttpClient = client
	}
}

func WithOffline(offline bool) Option {
	return func(p *Parser) {
		p.offline = offline
	}
}

func WithSize(size int64) Option {
	return func(p *Parser) {
		p.size = size
	}
}

func WithDBDir(dbDir string) Option {
	return func(p *Parser) {
		p.dbSearcher = db.NewSearcher(dbDir)
	}
}

func NewParser(opts ...Option) types.Parser {
	// for HTTP retry
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = logger{}
	retryClient.RetryWaitMin = 20 * time.Second
	retryClient.RetryWaitMax = 5 * time.Minute
	retryClient.RetryMax = 5
	client := retryClient.StandardClient()

	// attempt to read the maven central api url from os environment, if it's
	// not set use the default
	mavenURL, ok := os.LookupEnv("MAVEN_CENTRAL_URL")
	if !ok {
		mavenURL = baseURL
	}

	dbDir, ok := os.LookupEnv("TRIVY_JAVA_DB_DIR")
	if !ok {
		cacheDir, err := os.UserCacheDir()
		if err == nil {
			dbDir = filepath.Join(cacheDir, baseDBDir)
		}

	}

	p := &Parser{
		mavenSearcher: maven.NewSearcher(mavenURL, client),
		dbSearcher:    db.NewSearcher(dbDir),
	}

	for _, opt := range opts {
		opt(p)
	}

	return p
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	return p.parseArtifact(p.rootFilePath, p.size, r)
}

func (p *Parser) parseArtifact(fileName string, size int64, r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	log.Logger.Debugw("Parsing Java artifacts...", zap.String("file", fileName))

	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, nil, xerrors.Errorf("zip error: %w", err)
	}

	// Try to extract artifactId and version from the file name
	// e.g. spring-core-5.3.4-SNAPSHOT.jar => sprint-core, 5.3.4-SNAPSHOT
	fileName = filepath.Base(fileName)
	fileProps := parseFileName(fileName)

	var libs []types.Library
	var m manifest
	var foundPomProps bool

	for _, fileInJar := range zr.File {
		switch {
		case filepath.Base(fileInJar.Name) == "pom.properties":
			props, err := parsePomProperties(fileInJar)
			if err != nil {
				return nil, nil, xerrors.Errorf("failed to parse %s: %w", fileInJar.Name, err)
			}
			libs = append(libs, props.Library())

			// Check if the pom.properties is for the original JAR/WAR/EAR
			if fileProps.ArtifactID == props.ArtifactID && fileProps.Version == props.Version {
				foundPomProps = true
			}
		case filepath.Base(fileInJar.Name) == "MANIFEST.MF":
			m, err = parseManifest(fileInJar)
			if err != nil {
				return nil, nil, xerrors.Errorf("failed to parse MANIFEST.MF: %w", err)
			}
		case isArtifact(fileInJar.Name):
			innerLibs, _, err := p.parseInnerJar(fileInJar) //TODO process inner deps
			if err != nil {
				log.Logger.Debugf("Failed to parse %s: %s", fileInJar.Name, err)
				continue
			}
			libs = append(libs, innerLibs...)
		}
	}

	// If pom.properties is found, it should be preferred than MANIFEST.MF.
	if foundPomProps {
		return libs, nil, nil
	}

	var searchers []searchers.Searcher
	// enable search from trivy-java-db
	err = p.dbSearcher.InitDB()
	if err == nil && p.dbSearcher.DBDir != "" {
		searchers = append(searchers, p.dbSearcher)
	} else {
		log.Logger.Warnf("can't init trivy-java-db: %s", err)
	}

	// enable search maven repository
	if !p.offline {
		searchers = append(searchers, p.mavenSearcher)
	} else {
		log.Logger.Debug("search GAV from maven repository disabled in offline mode")
	}

	manifestProps := m.properties()
	for _, s := range searchers {
		if digest, err := getSha1(r); err == nil {
			// If groupId and artifactId are not found, use Searchers to find GAV with SHA-1 digest.
			props, err := s.SearchBySHA1(digest)
			if err == nil {
				return append(libs, props.Library()), nil, nil
			} else if !errors.Is(err, jtypes.ArtifactNotFoundErr) {
				return nil, nil, xerrors.Errorf("failed to search by SHA1: %w", err)
			}
		}

		log.Logger.Debugw("No such 'jar' in "+s.GetSearcherName(), zap.String("file", fileName))

		// Return when artifactId or version from the file name are empty
		if fileProps.ArtifactID == "" || fileProps.Version == "" {
			continue
		}

		// Try to search groupId by artifactId via sonatype API
		// When some artifacts have the same groupIds, it might result in false detection.
		fileProps.GroupID, err = s.SearchByArtifactID(fileProps.ArtifactID)
		if err == nil {
			log.Logger.Debugw("POM was determined in a heuristic way", zap.String("file", fileName),
				zap.String("artifact", fileProps.String()))
			return append(libs, fileProps.Library()), nil, nil
		} else if !errors.Is(err, jtypes.ArtifactNotFoundErr) {
			return nil, nil, xerrors.Errorf("failed to search by artifact id: %w", err)
		}

	}
	// if props didn't find with Searcher:
	// insert props if props are valid
	if manifestProps.Valid() {
		libs = append(libs, manifestProps.Library())
	}
	return libs, nil, nil
}

func (p *Parser) parseInnerJar(zf *zip.File) ([]types.Library, []types.Dependency, error) {
	fr, err := zf.Open()
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to open %s: %w", zf.Name, err)
	}

	f, err := os.CreateTemp("", "inner")
	if err != nil {
		return nil, nil, xerrors.Errorf("unable to create a temp file: %w", err)
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()

	// Copy the file content to the temp file
	if _, err = io.Copy(f, fr); err != nil {
		return nil, nil, xerrors.Errorf("file copy error: %w", err)
	}

	// Parse jar/war/ear recursively
	innerLibs, innerDeps, err := p.parseArtifact(zf.Name, int64(zf.UncompressedSize64), f)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to parse %s: %w", zf.Name, err)
	}

	return innerLibs, innerDeps, nil
}

func isArtifact(name string) bool {
	ext := filepath.Ext(name)
	if ext == ".jar" || ext == ".ear" || ext == ".war" {
		return true
	}
	return false
}

func parseFileName(fileName string) jtypes.Properties {
	packageVersion := jarFileRegEx.FindStringSubmatch(fileName)
	if len(packageVersion) != 3 {
		return jtypes.Properties{}
	}

	return jtypes.Properties{
		ArtifactID: packageVersion[1],
		Version:    packageVersion[2],
	}
}

func parsePomProperties(f *zip.File) (jtypes.Properties, error) {
	file, err := f.Open()
	if err != nil {
		return jtypes.Properties{}, xerrors.Errorf("unable to open pom.properties: %w", err)
	}
	defer file.Close()

	var p jtypes.Properties
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "groupId="):
			p.GroupID = strings.TrimPrefix(line, "groupId=")
		case strings.HasPrefix(line, "artifactId="):
			p.ArtifactID = strings.TrimPrefix(line, "artifactId=")
		case strings.HasPrefix(line, "version="):
			p.Version = strings.TrimPrefix(line, "version=")
		}
	}

	if err = scanner.Err(); err != nil {
		return jtypes.Properties{}, xerrors.Errorf("scan error: %w", err)
	}
	return p, nil
}

type manifest struct {
	implementationVersion  string
	implementationTitle    string
	implementationVendor   string
	implementationVendorId string
	specificationTitle     string
	specificationVersion   string
	specificationVendor    string
	bundleName             string
	bundleVersion          string
	bundleSymbolicName     string
}

func parseManifest(f *zip.File) (manifest, error) {
	file, err := f.Open()
	if err != nil {
		return manifest{}, xerrors.Errorf("unable to open MANIFEST.MF: %w", err)
	}
	defer file.Close()

	var m manifest
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Skip variables. e.g. Bundle-Name: %bundleName
		ss := strings.Fields(line)
		if len(ss) <= 1 || (len(ss) > 1 && strings.HasPrefix(ss[1], "%")) {
			continue
		}

		// It is not determined which fields are present in each application.
		// In some cases, none of them are included, in which case they cannot be detected.
		switch {
		case strings.HasPrefix(line, "Implementation-Version:"):
			m.implementationVersion = strings.TrimPrefix(line, "Implementation-Version:")
		case strings.HasPrefix(line, "Implementation-Title:"):
			m.implementationTitle = strings.TrimPrefix(line, "Implementation-Title:")
		case strings.HasPrefix(line, "Implementation-Vendor:"):
			m.implementationVendor = strings.TrimPrefix(line, "Implementation-Vendor:")
		case strings.HasPrefix(line, "Implementation-Vendor-Id:"):
			m.implementationVendorId = strings.TrimPrefix(line, "Implementation-Vendor-Id:")
		case strings.HasPrefix(line, "Specification-Version:"):
			m.specificationVersion = strings.TrimPrefix(line, "Specification-Version:")
		case strings.HasPrefix(line, "Specification-Title:"):
			m.specificationTitle = strings.TrimPrefix(line, "Specification-Title:")
		case strings.HasPrefix(line, "Specification-Vendor:"):
			m.specificationVendor = strings.TrimPrefix(line, "Specification-Vendor:")
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

func (m manifest) properties() jtypes.Properties {
	groupID, err := m.determineGroupID()
	if err != nil {
		return jtypes.Properties{}
	}

	artifactID, err := m.determineArtifactID()
	if err != nil {
		return jtypes.Properties{}
	}

	version, err := m.determineVersion()
	if err != nil {
		return jtypes.Properties{}
	}

	return jtypes.Properties{
		GroupID:    groupID,
		ArtifactID: artifactID,
		Version:    version,
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
	case m.implementationVendor != "":
		groupID = m.implementationVendor
	case m.specificationVendor != "":
		groupID = m.specificationVendor
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

func getSha1(r io.ReadSeeker) (string, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", xerrors.Errorf("file seek error: %w", err)
	}

	h := sha1.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", xerrors.Errorf("unable to calculate SHA-1: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
