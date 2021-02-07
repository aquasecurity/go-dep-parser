package pom

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	multierror "github.com/hashicorp/go-multierror"
	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

const (
	centralURL = "https://repo.maven.apache.org/maven2/"
)

var (
	varRegexp = regexp.MustCompile(`\${(\S+?)}`)
)

type parser struct {
	rootPath           string
	cache              pomCache
	localRepository    string
	remoteRepositories []string
}

func newParser(filePath string) *parser {
	s := readSettings()
	localRepository := s.LocalRepository
	if localRepository == "" {
		homeDir, _ := os.UserHomeDir()
		localRepository = filepath.Join(homeDir, ".m2", "repository")
	}

	return &parser{
		rootPath:           filepath.Clean(filePath),
		cache:              newPOMCache(),
		localRepository:    localRepository,
		remoteRepositories: []string{centralURL},
	}
}

func (p *parser) Parse(r io.Reader) ([]types.Library, error) {
	root, err := parsePom(r)
	if err != nil {
		return nil, err
	}

	return p.parseRoot(&pom{
		filePath: p.rootPath,
		content:  root,
	})
}

func (p *parser) parseRoot(root *pom) ([]types.Library, error) {
	// Analyze root POM
	result, err := p.analyze(root)
	if err != nil {
		return nil, err
	}

	// Prepare a queue for dependencies
	queue := newArtifactQueue()

	// Cache and enqueue root POM
	p.cache.put(result.artifact, result)
	queue.enqueue(result.artifact)

	uniqArtifacts := map[string]version{}

	// Iterate direct and transitive dependencies
	for !queue.IsEmpty() {
		art := queue.dequeue()
		fmt.Println(art.name(), art.Version.String())

		// For soft requirements, skip dependency resolution that has already been resolved.
		if v, ok := uniqArtifacts[art.name()]; ok {
			if !v.shouldOverride(art.Version) {
				continue
			}
		}

		result, err = p.resolve(art)
		if err != nil {
			return nil, xerrors.Errorf("resolve error (%s:%s): %w", art.name(), art.Version, err)
		}

		// Parse, cache, and enqueue modules.
		for _, relativePath := range result.modules {
			moduleArtifact, err := p.parseModule(result.filePath, relativePath)
			if err != nil {
				return nil, err
			}

			queue.enqueue(moduleArtifact)
		}

		// Resolve transitive dependencies later
		queue.enqueue(result.dependencies...)

		for _, d := range result.dependencies {
			if d.ArtifactID == "jsch.agentproxy" && d.Version.String() == "0.0.6" {
				fmt.Println("========================================")
				fmt.Println(art.GroupID, art.ArtifactID, art.Version)
				fmt.Println("========================================")
			}
		}

		// Override the version
		uniqArtifacts[art.name()] = art.Version
	}

	// Convert to []types.Library
	var libs []types.Library
	for name, version := range uniqArtifacts {
		libs = append(libs, types.Library{
			Name:    name,
			Version: version.String(),
		})
	}

	return libs, nil
}

func (p *parser) parseModule(currentPath, relativePath string) (artifact, error) {
	// modulePath: "root/" + "module/" => "root/module"
	module, err := p.openRelativePom(currentPath, relativePath)
	if err != nil {
		return artifact{}, err
	}

	result, err := p.analyze(module)
	if err != nil {
		return artifact{}, err
	}

	moduleArtifact := module.artifact()
	p.cache.put(moduleArtifact, result)

	return moduleArtifact, nil
}

func (p *parser) resolve(art artifact) (analysisResult, error) {
	// If the artifact is found in cache, it is returned.
	if result := p.cache.get(art); result != nil {
		return *result, nil
	}

	pomContent, err := p.tryRepository(art.GroupID, art.ArtifactID, art.Version.String())
	if err != nil {
		return analysisResult{}, err
	}
	result, err := p.analyze(pomContent)
	if err != nil {
		return analysisResult{}, err
	}

	p.cache.put(art, result)
	return result, nil
}

type analysisResult struct {
	filePath             string
	artifact             artifact
	dependencies         []artifact
	dependencyManagement map[string]string
	properties           map[string]string
	modules              []string
}

func (p *parser) analyze(pom *pom) (analysisResult, error) {
	if pom == nil || pom.content == nil {
		return analysisResult{}, nil
	}

	// Update remoteRepositories
	p.remoteRepositories = unique(append(p.remoteRepositories, pom.repositories()...))

	// Parent
	parent, err := p.parseParent(pom.filePath, pom.content.Parent)
	if err != nil {
		return analysisResult{}, err
	}

	// Merge parent
	pom.merge(parent)

	// Generate properties
	props := pom.properties()

	// Extract and merge dependencies under "dependencyManagement"
	depManagement := p.dependencyManagement(pom.content.DependencyManagement.Dependencies.Dependency, props)
	depManagement = mergeMaps(parent.dependencyManagement, depManagement)

	// Merge dependencies. Child dependencies must be preferred than parent dependencies.
	deps := p.parseDependencies(pom.content.Dependencies.Dependency, props, depManagement)
	deps = append(deps, parent.dependencies...)

	return analysisResult{
		filePath:             pom.filePath,
		artifact:             pom.artifact(),
		dependencies:         deps,
		dependencyManagement: depManagement,
		properties:           props,
		modules:              pom.content.Modules.Module,
	}, nil
}

func resolveDependency(dep pomDependency, props properties, depManagement map[string]string) artifact {
	art := newArtifact(dep.GroupId, dep.ArtifactId, dep.Version, props)
	if art.Version.String() == "" {
		if ver, ok := depManagement[art.name()]; ok {
			art.Version = newVersion(ver)
		}
	}
	return art
}

func (p parser) dependencyManagement(deps []pomDependency, props properties) map[string]string {
	depManagement := map[string]string{}
	for _, d := range deps {
		art := newArtifact(d.GroupId, d.ArtifactId, d.Version, props)

		// https://howtodoinjava.com/maven/maven-dependency-scopes/#import
		if d.Scope == "import" {
			result, err := p.resolve(art)
			if err == nil {
				depManagement = mergeMaps(depManagement, result.dependencyManagement)
			}
			continue
		}
		depManagement[art.name()] = art.Version.String()
	}
	return depManagement
}

func (p parser) parseParent(currentPath string, parent pomParent) (
	analysisResult, error) {
	// Pass nil properties so that variables in <parent> are not evaluated.
	target := newArtifact(parent.GroupId, parent.ArtifactId, parent.Version, nil)
	if target.isEmpty() {
		return analysisResult{}, nil
	}

	// If the artifact is found in cache, it is returned.
	if result := p.cache.get(target); result != nil {
		return *result, nil
	}

	parentPOM, err := p.retrieveParent(currentPath, parent.RelativePath, target)
	if err != nil {
		return analysisResult{}, err
	}

	result, err := p.analyze(parentPOM)
	if err != nil {
		return analysisResult{}, err
	}

	p.cache.put(target, result)

	return result, nil
}

func (p parser) retrieveParent(currentPath, relativePath string, target artifact) (*pom, error) {
	var errs error

	// Try relativePath
	if relativePath != "" {
		pom, err := p.tryRelativePath(target, currentPath, relativePath)
		if err != nil {
			errs = multierror.Append(errs, err)
		} else {
			return pom, nil
		}
	}

	// If not found, search the parent director
	pom, err := p.tryRelativePath(target, currentPath, "../pom.xml")
	if err != nil {
		errs = multierror.Append(errs, err)
	} else {
		return pom, nil
	}

	// If not found, search local/remote remoteRepositories
	pom, err = p.tryRepository(target.GroupID, target.ArtifactID, target.Version.String())
	if err != nil {
		errs = multierror.Append(errs, err)
	} else {
		return pom, nil
	}

	// Reaching here means the POM wasn't found
	return nil, errs
}

func (p parser) tryRelativePath(parentArtifact artifact, currentPath, relativePath string) (*pom, error) {
	pom, err := p.openRelativePom(currentPath, relativePath)
	if err != nil {
		return nil, err
	}

	result, err := p.analyze(pom)
	if err != nil {
		return nil, err
	}

	if !parentArtifact.equal(result.artifact) {
		return nil, xerrors.New("'parent.relativePath' points at wrong local POM")
	}

	return pom, nil
}

func (p parser) parseDependencies(deps []pomDependency, props, depManagement map[string]string) []artifact {
	var dependencies []artifact
	for _, d := range deps {
		if (d.Scope != "" && d.Scope != "compile") || d.Optional {
			continue
		}
		dependencies = append(dependencies, resolveDependency(d, props, depManagement))
	}
	return dependencies
}

func (p parser) openRelativePom(currentPath, relativePath string) (*pom, error) {
	// e.g. child/pom.xml => child/
	dir := filepath.Dir(currentPath)

	// e.g. child + ../parent => parent/
	filePath := filepath.Join(dir, relativePath)

	isDir, err := isDirectory(filePath)
	if err != nil {
		return nil, err
	} else if isDir {
		// e.g. parent/ => parent/pom.xml
		filePath = filepath.Join(filePath, "pom.xml")
	}

	pom, err := p.openPom(filePath)
	if err != nil {
		return nil, err
	}
	return pom, nil
}

func (p parser) openPom(filePath string) (*pom, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	content, err := parsePom(f)
	if err != nil {
		return nil, err
	}
	return &pom{
		filePath: filePath,
		content:  content,
	}, nil
}
func (p parser) tryRepository(groupID, artifactID, version string) (*pom, error) {
	// Generate a proper path to the pom.xml
	// e.g. com.fasterxml.jackson.core, jackson-annotations, 2.10.0
	//      => com/fasterxml/jackson/core/jackson-annotations/2.10.0/jackson-annotations-2.10.0.pom
	paths := strings.Split(groupID, ".")
	paths = append(paths, artifactID, version)
	paths = append(paths, fmt.Sprintf("%s-%s.pom", artifactID, version))

	// Search local remoteRepositories
	pom, err := p.loadPOMFromLocalRepository(paths)
	if err == nil {
		return pom, nil
	}

	// Search remote remoteRepositories
	pom, err = p.fetchPOMFromRemoteRepository(paths)
	if err != nil {
		fmt.Println(err)
	}
	if err == nil {
		return pom, nil
	}

	return nil, xerrors.Errorf("%s:%s:%s was not found in local/remote repositories", groupID, artifactID, version)
}

func (p parser) loadPOMFromLocalRepository(paths []string) (*pom, error) {
	paths = append([]string{p.localRepository}, paths...)
	localPath := filepath.Join(paths...)

	return p.openPom(localPath)
}

func (p parser) fetchPOMFromRemoteRepository(paths []string) (*pom, error) {
	// try all remoteRepositories
	for _, repo := range p.remoteRepositories {
		url := repo + path.Join(paths...)
		fmt.Println(url)
		resp, err := http.Get(url)
		if err != nil || resp.StatusCode != http.StatusOK {
			fmt.Println(paths)
			if resp != nil {
				fmt.Printf("%s returns %d\n", url, resp.StatusCode)
			}
			continue
		}

		content, err := parsePom(resp.Body)
		if err != nil {
			return nil, err
		}

		return &pom{
			filePath: "", // from remote remoteRepositories
			content:  content,
		}, nil
	}
	return nil, xerrors.Errorf("the POM was not found in remote remoteRepositories")
}

func parsePom(r io.Reader) (*pomXML, error) {
	pom := &pomXML{}
	decoder := xml.NewDecoder(r)
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(pom); err != nil {
		return nil, err
	}
	return pom, nil
}
