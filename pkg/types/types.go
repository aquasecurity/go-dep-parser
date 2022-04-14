package types

import "fmt"

type Library struct {
	Name    string
	Version string
	License string `json:",omitempty"`
}

type Dependency struct {
	ID        string
	DependsOn []string
}

func ID(lib Library) string {
	// TODO replace naive implementation
	return fmt.Sprintf("%s@%s", lib.Name, lib.Version)
}
