package pom

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"golang.org/x/exp/slices"
)

var (
	varRegexp = regexp.MustCompile(`\${(\S+?)}`)
)

type artifact struct {
	GroupID    string
	ArtifactID string
	Version    version
	Module     bool
	Exclusions map[string]struct{}
}

func newArtifact(groupID, artifactID, version string, props map[string]string) artifact {
	return artifact{
		GroupID:    evaluateVariable(groupID, props, nil),
		ArtifactID: evaluateVariable(artifactID, props, nil),
		Version:    newVersion(evaluateVariable(version, props, nil)),
	}
}

func (a artifact) IsEmpty() bool {
	return a.GroupID == "" || a.ArtifactID == "" || a.Version.String() == ""
}

func (a artifact) Equal(o artifact) bool {
	return a.GroupID == o.GroupID || a.ArtifactID == o.ArtifactID || a.Version.String() == o.Version.String()
}

func (a artifact) Inherit(parent artifact) artifact {
	// inherited from a parent
	if a.GroupID == "" {
		a.GroupID = parent.GroupID
	}

	if a.Version.String() == "" {
		a.Version = parent.Version
	}
	return a
}

func (a artifact) Name() string {
	return fmt.Sprintf("%s:%s", a.GroupID, a.ArtifactID)
}

func (a artifact) String() string {
	return fmt.Sprintf("%s:%s", a.Name(), a.Version)
}

type version struct {
	ver  string
	hard bool
}

// Only soft and hard requirements for the specified version are supported at the moment.
func newVersion(s string) version {
	var hard bool
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = strings.Trim(s, "[]")
		hard = true
	}

	// TODO: Other requirements are not supported
	if strings.ContainsAny(s, ",()[]") {
		s = ""
	}

	return version{
		ver:  s,
		hard: hard,
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

func evaluateVariable(s string, props map[string]string, usedProps []string) string {
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
			ss, ok := props[m[1]]
			if ok {
				// search for looped properties
				if slices.Contains(usedProps, ss) {
					printLoopedPropertiesStack(m[0], usedProps)
					return ""
				}
				usedProps = append(usedProps, ss) // save received props to check if we get this prop again
				newValue = evaluateVariable(ss, props, usedProps)
				usedProps = []string{} // clear props if we returned from recursive. Required for correct work with 2 same props like ${foo}-${foo}
			}

		}
		s = strings.ReplaceAll(s, m[0], newValue)
	}
	return s
}

func printLoopedPropertiesStack(env string, usedProps []string) {
	var s string
	for _, prop := range usedProps {
		s += fmt.Sprintf("%s -> ", prop)
	}
	log.Logger.Warnf("Lopped properties were detected: %s%s", s, env)
}
