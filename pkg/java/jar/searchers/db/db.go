package db

import (
	jtypes "github.com/aquasecurity/go-dep-parser/pkg/java/jar/types"
	"github.com/aquasecurity/trivy-java-db/pkg/db"
	"github.com/aquasecurity/trivy-java-db/pkg/types"
	"golang.org/x/xerrors"
)

const searcherName = "trivy-java-db"

type Searcher struct {
	DBDir string
}

func NewSearcher(dbDir string) Searcher {
	return Searcher{DBDir: dbDir}
}

func (s Searcher) InitDB() error {
	if s.DBDir == "" {
		return nil
	}
	return db.Init(s.DBDir)
}

func (s Searcher) Exists(groupID, artifactID string) (bool, error) {
	index := db.SelectIndexByArtifactIDAndGroupID(groupID, artifactID)
	return index.ArtifactID != "", nil
}

func (s Searcher) SearchBySHA1(sha1 string) (jtypes.Properties, error) {
	index := db.SelectIndexBySha1(sha1)
	if index.ArtifactID == "" {
		return jtypes.Properties{}, xerrors.Errorf("digest %s: %w", sha1, jtypes.ArtifactNotFoundErr)
	}
	props := jtypes.Properties{
		GroupID:    index.GroupID,
		ArtifactID: index.ArtifactID,
		Version:    index.Version,
	}

	return props, nil
}

func (s Searcher) SearchByArtifactID(artifactID string) (string, error) {
	indexes := db.SelectIndexesByArtifactIDAndFileType(artifactID, types.JarType)
	if len(indexes) == 0 {
		return "", xerrors.Errorf("artifactID %s: %w", artifactID, jtypes.ArtifactNotFoundErr)
	}

	// Some artifacts might have the same artifactId.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	groupIDs := map[string]int{}
	for _, index := range indexes {
		if i, ok := groupIDs[index.GroupID]; ok {
			groupIDs[index.GroupID] = i + 1
			continue
		}
		groupIDs[index.GroupID] = 1
	}
	maxCount := 0
	var groupID string
	for k, v := range groupIDs {
		if v > maxCount {
			groupID = k
		}
	}

	return groupID, nil
}

// GetSearcherName return searcher name to insert in logs
func (s Searcher) GetSearcherName() string {
	return searcherName
}
