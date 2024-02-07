package types

import (
	"sort"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
)

type Library struct {
	ID                 string `json:",omitempty"`
	Name               string
	Version            string
	Dev                bool
	Indirect           bool          `json:",omitempty"`
	Licenses           Licenses      `json:",omitempty"`
	ExternalReferences []ExternalRef `json:",omitempty"`
	Locations          Locations     `json:",omitempty"`
	FilePath           string        `json:",omitempty"` // Required to show nested jars
}

type Libraries []Library

func (libs Libraries) Len() int { return len(libs) }
func (libs Libraries) Less(i, j int) bool {
	if libs[i].ID != libs[j].ID { // ID could be empty
		return libs[i].ID < libs[j].ID
	} else if libs[i].Name != libs[j].Name { // Name could be the same
		return libs[i].Name < libs[j].Name
	}
	return libs[i].Version < libs[j].Version
}
func (libs Libraries) Swap(i, j int) { libs[i], libs[j] = libs[j], libs[i] }

// Location in lock file
type Location struct {
	StartLine int `json:",omitempty"`
	EndLine   int `json:",omitempty"`
}

type Locations []Location

func (locs Locations) Len() int { return len(locs) }
func (locs Locations) Less(i, j int) bool {
	return locs[i].StartLine < locs[j].StartLine
}
func (locs Locations) Swap(i, j int) { locs[i], locs[j] = locs[j], locs[i] }

type ExternalRef struct {
	Type RefType
	URL  string
}

type Dependency struct {
	ID        string
	DependsOn []string
}

type Dependencies []Dependency

func (deps Dependencies) Len() int { return len(deps) }
func (deps Dependencies) Less(i, j int) bool {
	return deps[i].ID < deps[j].ID
}
func (deps Dependencies) Swap(i, j int) { deps[i], deps[j] = deps[j], deps[i] }

type License struct {
	Value string      `json:",omitempty"`
	Type  LicenseType `json:",omitempty"`
}

type LicenseType string

const (
	LicenseTypeName         LicenseType = "name"          // license name or expression
	LicenseTypeFile         LicenseType = "file"          // filename for license file
	LicenseTypeNonSeparable LicenseType = "non-separable" // text of license without possible to split
)

type Licenses []License

func LicensesFromString(s string, typ LicenseType) Licenses {
	if s == "" {
		return nil
	}

	return Licenses{
		{
			Type:  typ,
			Value: s,
		},
	}
}

func LicensesFromStringSlice(ss []string, typ LicenseType) Licenses {
	if len(ss) == 0 {
		return nil
	}

	licenses := make(Licenses, 0, len(ss))
	for _, s := range ss {
		licenses = append(licenses, LicensesFromString(s, typ)...)
	}
	sort.Sort(licenses)
	return licenses
}

func (licenses Licenses) Len() int { return len(licenses) }
func (licenses Licenses) Less(i, j int) bool {
	return licenses[i].Value < licenses[j].Value
}
func (licenses Licenses) Swap(i, j int) { licenses[i], licenses[j] = licenses[j], licenses[i] }

type Parser interface {
	// Parse parses the dependency file
	Parse(r dio.ReadSeekerAt) ([]Library, []Dependency, error)
}

type RefType string

const (
	RefWebsite      RefType = "website"
	RefLicense      RefType = "license"
	RefVCS          RefType = "vcs"
	RefIssueTracker RefType = "issue-tracker"
	RefOther        RefType = "other"
)
