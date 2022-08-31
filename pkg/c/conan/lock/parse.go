package lock

import (
	"encoding/json"
	"strings"
	"sync"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/log"
	"github.com/aquasecurity/go-dep-parser/pkg/types"

	"golang.org/x/xerrors"
)

type LockFile struct {
	GraphLock GraphLock `json:"graph_lock"`
}

type GraphLock struct {
	Nodes map[string]Nod `json:"nodes"`
}

type Nod struct {
	Ref string `json:"ref"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var once sync.Once
	var lock LockFile
	var libs []types.Library

	decoder := json.NewDecoder(r)
	if err := decoder.Decode(&lock); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode conan.lock file: %s", err.Error())
	}

	for _, nod := range lock.GraphLock.Nodes {
		if nod.Ref != "" {
			// ref format examples: 'pkga/0.1@user/testing'
			// 'pkgb/0.1.0'
			// 'pkgc/system'
			ref := strings.Split(strings.Split(nod.Ref, "@")[0], "/")
			if len(ref) != 2 {
				once.Do(func() {
					log.Logger.Debugw("Unable to detect conan dependency: %s", ref)
				})
				continue
			}

			libs = append(libs, types.Library{
				Name:    ref[0],
				Version: ref[1],
			})
		}
	}
	return libs, nil, nil
}
