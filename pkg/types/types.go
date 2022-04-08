package types

import "fmt"

type Library struct {
	ID      string
	Name    string
	Version string
	License string `json:",omitempty"`
}

type Dependency struct {
	Id        string
	DependsOn []string
}

func NewLibrary(name, version, license string) Library {
	// TODO replace naive implementation
	return Library{
		ID:      fmt.Sprintf("%s@%s", name, version),
		Name:    name,
		Version: version,
		License: license,
	}
}
