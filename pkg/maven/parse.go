package maven

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

const (
	separator       = ":"
	resolvedSection = "The following files have been resolved:"
)

type Artifact struct {
	GroupID    string
	ArtifactID string
	Type       string
	Classifier string
	Version    string
	Scope      string
}

func (a Artifact) getName() string {
	return a.GroupID + separator + a.ArtifactID
}

func Parse(r io.Reader) ([]types.Library, error) {
	scanner := bufio.NewScanner(r)

	var libs []types.Library
	var resolvedSectionFlag bool
	for scanner.Scan() {

		line := scanner.Text()
		if line == resolvedSection {
			resolvedSectionFlag = true
			continue
		}
		if resolvedSectionFlag && line == "" {
			break
		}
		if !resolvedSectionFlag {
			continue
		}

		line = strings.TrimSpace(line)
		if line == "none" {
			return []types.Library{}, nil
		}

		artifact, err := parseArtifact(strings.Fields(line)[0])
		if err != nil {
			return nil, xerrors.Errorf("failed to parse artifact: %w", err)
		}
		libs = append(libs, types.Library{
			Name:    artifact.getName(),
			Version: artifact.Version,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	return libs, nil
}

func parseArtifact(s string) (Artifact, error) {
	ss := strings.Split(s, separator)
	if len(ss) < 4 {
		fmt.Println(s)
		return Artifact{}, xerrors.New("invalid format error")
	}
	artifact := Artifact{
		GroupID:    ss[0],
		ArtifactID: ss[1],
		Type:       ss[2],
	}
	switch len(ss) {
	case 4:
		artifact.Version = ss[3]
	case 5:
		artifact.Version = ss[3]
		artifact.Scope = ss[4]
	case 6:
		artifact.Classifier = ss[3]
		artifact.Version = ss[4]
		artifact.Scope = ss[5]
	}

	return artifact, nil
}
