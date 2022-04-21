package types

type Library struct {
	Name     string
	Version  string
	Indirect bool   `json:",omitempty"`
	License  string `json:",omitempty"`
}

type Dependency struct {
	ID        string
	DependsOn []string
}
