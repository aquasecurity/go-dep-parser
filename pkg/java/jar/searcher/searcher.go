package searcher

import (
	jtypes "github.com/aquasecurity/go-dep-parser/pkg/java/jar/types"
)

type Searcher interface {
	Exists(groupID, artifactID string) (bool, error)
	SearchBySHA1(sha1 string) (jtypes.Properties, error)
	SearchByArtifactID(artifactID string) (string, error)
}

type GAV struct {
}
