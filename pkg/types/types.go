package types

type Library struct {
	Name    string
	Version string
}

type EmbeddedLibrary struct {
	ParentDependencies []string
	Name               string
	Version            string
}
