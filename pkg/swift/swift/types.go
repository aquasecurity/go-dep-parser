package swift

type LockFile struct {
	Object Object `json:"object"`
}

type Object struct {
	Pins []Pin `json:"pins"`
}

type Pin struct {
	Package       string `json:"package"`
	RepositoryURL string `json:"repositoryURL"`
	State         State  `json:"state"`
	StartLine     int
	EndLine       int
}

type State struct {
	Branch   any    `json:"branch"`
	Revision string `json:"revision"`
	Version  string `json:"version"`
}
