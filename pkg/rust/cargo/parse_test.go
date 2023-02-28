package cargo

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

var (
	cargoNormalLibs = []types.Library{
		{ID: "normal@0.1.0", Name: "normal", Version: "0.1.0", Locations: []types.Location{{StartLine: 8, EndLine: 13}}},
		{ID: "libc@0.2.54", Name: "libc", Version: "0.2.54", Locations: []types.Location{{StartLine: 3, EndLine: 6}}},
		{ID: "typemap@0.3.3", Name: "typemap", Version: "0.3.3", Locations: []types.Location{{StartLine: 15, EndLine: 21}}},
		{ID: "url@1.7.2", Name: "url", Version: "1.7.2", Locations: []types.Location{{StartLine: 23, EndLine: 31}}},
	}
	cargoNormalDeps = []types.Dependency{
		{
			ID:        "normal@0.1.0",
			DependsOn: []string{"libc@0.2.54"}},
		{
			ID:        "typemap@0.3.3",
			DependsOn: []string{"unsafe-any@0.4.2"},
		},
		{
			ID:        "url@1.7.2",
			DependsOn: []string{"idna@0.1.5", "matches@0.1.8", "percent-encoding@1.0.1"},
		},
	}
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file     string // Test input file
		wantLibs []types.Library
		wantDeps []types.Dependency
	}{
		{
			file:     "testdata/cargo_normal.lock",
			wantLibs: cargoNormalLibs,
			wantDeps: cargoNormalDeps,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			libs, deps, err := NewParser().Parse(f)

			require.NoError(t, err)

			sort.Slice(libs, func(i, j int) bool {
				ret := strings.Compare(libs[i].Name, libs[j].Name)
				if ret == 0 {
					return libs[i].Version < libs[j].Version
				}
				return ret < 0
			})

			sort.Slice(v.wantLibs, func(i, j int) bool {
				ret := strings.Compare(v.wantLibs[i].Name, v.wantLibs[j].Name)
				if ret == 0 {
					return v.wantLibs[i].Version < v.wantLibs[j].Version
				}
				return ret < 0
			})

			assert.Equal(t, v.wantLibs, libs)

			assert.Equal(t, v.wantDeps, deps)
		})
	}
}
