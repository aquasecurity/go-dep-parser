package types

import dio "github.com/aquasecurity/go-dep-parser/pkg/io"

type Library struct {
	ID                 string `json:",omitempty"`
	Name               string
	Version            string
	Indirect           bool          `json:",omitempty"`
	License            string        `json:",omitempty"`
	ExternalReferences []ExternalRef `json:",omitempty"`
}

type ExternalRef struct {
	Type RefType
	URL  string
}

type Dependency struct {
	ID        string
	DependsOn []string
}

type Parser interface {
	// Parse parses the dependency file
	Parse(r dio.ReadSeekerAt) ([]Library, []Dependency, error)
}

type RefType string

const (
	Website      RefType = "website"
	License      RefType = "license"
	VCS          RefType = "vcs"
	IssueTracker RefType = "issue-tracker"
	Other        RefType = "other"
)
