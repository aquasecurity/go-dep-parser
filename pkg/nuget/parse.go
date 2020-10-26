package nuget

import (
    "encoding/json"
    "io"

    "golang.org/x/xerrors"

    "github.com/aquasecurity/go-dep-parser/pkg/types"
)

type LockFile struct {
    Version int
    Targets map[string]Dependencies `json:"dependencies"`
}

type Dependencies map[string]Dependency

type Dependency struct {
    Type     string
    Resolved string
}

func Parse(r io.Reader) ([]types.Library, error) {
    var lockFile LockFile
    decoder := json.NewDecoder(r)

    if err := decoder.Decode(&lockFile); err != nil {
        return nil, xerrors.Errorf("failed to decode packages.lock.json: %w", err)
    }

    var libraries []types.Library
    unique := map[string]struct{}{}

    for _, targetContent := range lockFile.Targets {
        for packageName, packageContent := range targetContent {
            // If package type is "project", it is the actual project, and we skip it.
            if packageContent.Type == "Project" {
                continue
            }

            if _, ok := unique[packageName]; ok {
                continue
            }

            libraries = append(libraries, types.Library{
                Name:    packageName,
                Version: packageContent.Resolved,
            })

            unique[packageName] = struct{}{}
        }
    }

    return libraries, nil
}
