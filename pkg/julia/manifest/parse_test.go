package julia

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		file     string // Test input file
		want     []types.Library
		wantDeps []types.Dependency
	}{
		{
			name:     "Manifest v1.6",
			file:     "testdata/primary/Manifest_v1.6.toml",
			want:     juliaV1_6Libs,
			wantDeps: juliaV1_6Deps,
		},
		{
			name:     "Manifest v1.8",
			file:     "testdata/primary/Manifest_v1.8.toml",
			want:     juliaV1_8Libs,
			wantDeps: juliaV1_8Deps,
		},
		{
			name:     "no deps v1.6",
			file:     "testdata/no_deps_v1.6/Manifest.toml",
			want:     nil,
			wantDeps: nil,
		},
		{
			name:     "no deps v1.9",
			file:     "testdata/no_deps_v1.9/Manifest.toml",
			want:     nil,
			wantDeps: nil,
		},
		{
			name:     "dep extensions v1.9",
			file:     "testdata/dep_ext_v1.9/Manifest.toml",
			want:     juliaV1_9DepExtLibs,
			wantDeps: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, deps, err := NewParser().Parse(f)
			require.NoError(t, err)

			sortLibs(got)
			sortLibs(tt.want)

			assert.Equal(t, tt.want, got)
			if tt.wantDeps != nil {
				sortDeps(deps)
				sortDeps(tt.wantDeps)
				assert.Equal(t, tt.wantDeps, deps)
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
	for _, lib := range libs {
		sortLocations(lib.Locations)
	}
	sort.Slice(libs, func(i, j int) bool {
		return strings.Compare(libs[i].ID, libs[j].ID) < 0
	})
}

func sortLocations(locs []types.Location) {
	sort.Slice(locs, func(i, j int) bool {
		return locs[i].StartLine < locs[j].StartLine
	})
}
