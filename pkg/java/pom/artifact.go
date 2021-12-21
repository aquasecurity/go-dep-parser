package pom

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

var (
	varRegexp = regexp.MustCompile(`\${(\S+?)}`)
)

type artifact struct {
	GroupID    string
	ArtifactID string
	Version    version
	Module     bool
}

func newArtifact(groupID, artifactID, version string, props map[string]string) artifact {
	return artifact{
		GroupID:    evaluateVariable(groupID, props),
		ArtifactID: evaluateVariable(artifactID, props),
		Version:    newVersion(evaluateVariable(version, props)),
	}
}

func (a artifact) isEmpty() bool {
	return a.GroupID == "" || a.ArtifactID == "" || a.Version.String() == ""
}

func (a artifact) equal(o artifact) bool {
	return a.GroupID == o.GroupID || a.ArtifactID == o.ArtifactID || a.Version.String() == o.Version.String()
}

func (a artifact) inherit(parent artifact) artifact {
	// inherited from a parent
	if a.GroupID == "" {
		a.GroupID = parent.GroupID
	}

	if a.Version.String() == "" {
		a.Version = parent.Version
	}
	return a
}

func (a artifact) name() string {
	return fmt.Sprintf("%s:%s", a.GroupID, a.ArtifactID)
}

func (a artifact) String() string {
	return fmt.Sprintf("%s:%s", a.name(), a.Version)
}

type version struct {
	ver  string
	hard bool
}

// TODO: refine version requirements
// Only soft and hard requirements are supported at the moment.
func newVersion(s string) version {
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		return version{
			ver:  strings.Trim(s, "[]"),
			hard: true,
		}
	}
	return version{
		ver:  s,
		hard: false,
	}
}

func (v1 version) shouldOverride(v2 version) bool {
	if !v1.hard && v2.hard {
		return true
	}
	return false
}

func (v1 version) String() string {
	return v1.ver
}

func evaluateVariable(s string, props map[string]string) string {
	if props == nil {
		props = map[string]string{}
	}

	for _, m := range varRegexp.FindAllStringSubmatch(s, -1) {
		var newValue string

		// env.X: https://maven.apache.org/pom.html#Properties
		// e.g. env.PATH
		if strings.HasPrefix(m[1], "env.") {
			newValue = os.Getenv(strings.TrimPrefix(m[1], "env."))
		} else {
			// <properties> might include another property.
			// e.g. <animal.sniffer.skip>${skipTests}</animal.sniffer.skip>
			newValue = evaluateVariable(props[m[1]], props)
		}
		s = strings.ReplaceAll(s, m[0], newValue)
	}
	return s
}
