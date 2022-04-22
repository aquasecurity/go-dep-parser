package npm

import (
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file     string // Test input file
		want     []types.Library
		wantDeps []types.Dependency
	}{
		{
			file:     "testdata/package-lock_normal.json",
			want:     npmNormal,
			wantDeps: npmNormalDeps,
		},
		{
			file:     "testdata/package-lock_react.json",
			want:     npmReact,
			wantDeps: npmReactDeps,
		},
		{
			file:     "testdata/package-lock_with_dev.json",
			want:     npmWithDev,
			wantDeps: npmWithDevDeps,
		}, {
			file:     "testdata/package-lock_many.json",
			want:     npmMany,
			wantDeps: npmManyDeps,
		},
		{
			file:     "testdata/package-lock_nested.json",
			want:     npmNested,
			wantDeps: npmNestedDeps,
		},
		{
			file:     "testdata/package-lock_deep-nested.json",
			want:     npmDeepNested,
			wantDeps: npmDeepNestedDeps,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, deps, err := Parse(f)
			require.NoError(t, err)

			sortLibs(got)
			sortLibs(v.want)

			assert.Equal(t, v.want, got)
			if v.wantDeps != nil {
				sortDeps(deps)
				sortDeps(v.wantDeps)
				assert.Equal(t, v.wantDeps, deps)
			}
		})
	}
}

func sortDeps(deps []types.Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		return strings.Compare(deps[i].ID, deps[j].ID) < 0
	})

	for i := range deps {
		sort.Strings(deps[i].DependsOn)
	}
}

func sortLibs(libs []types.Library) {
	sort.Slice(libs, func(i, j int) bool {
		ret := strings.Compare(libs[i].Name, libs[j].Name)
		if ret == 0 {
			return libs[i].Version < libs[j].Version
		}
		return ret < 0
	})
}
