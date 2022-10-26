package yarn

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestGetPackageName(t *testing.T) {
	vectors := []struct {
		target   string // Test input file
		expect   string
		occurErr bool
	}{
		{
			target: `"@babel/code-frame@^7.0.0"`,
			expect: "@babel/code-frame",
		},
		{
			target: `grunt-contrib-cssmin@3.0.*:`,
			expect: "grunt-contrib-cssmin",
		},
		{
			target: "grunt-contrib-uglify-es@gruntjs/grunt-contrib-uglify#harmony:",
			expect: "grunt-contrib-uglify-es",
		},
		{
			target: `"jquery@git+https://xxxx:x-oauth-basic@github.com/tomoyamachi/jquery":`,
			expect: "jquery",
		},
		{
			target:   `normal line`,
			occurErr: true,
		},
	}

	for _, v := range vectors {
		actual, _, _, err := parsePackageLocators(v.target)

		if v.occurErr != (err != nil) {
			t.Errorf("expect error %t but err is %s", v.occurErr, err)
			continue
		}

		if actual != v.expect {
			t.Errorf("got %s, want %s, target :%s", actual, v.expect, v.target)
		}
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		file     string // Test input file
		want     []types.Library
		wantDeps []types.Dependency
	}{
		{
			name:     "normal",
			file:     "testdata/yarn_normal.lock",
			want:     yarnNormal,
			wantDeps: yarnNormalDeps,
		},
		{
			name:     "react",
			file:     "testdata/yarn_react.lock",
			want:     yarnReact,
			wantDeps: yarnReactDeps,
		},
		{
			name:     "yarn with dev",
			file:     "testdata/yarn_with_dev.lock",
			want:     yarnWithDev,
			wantDeps: yarnWithDevDeps,
		},
		{
			name:     "yarn many",
			file:     "testdata/yarn_many.lock",
			want:     yarnMany,
			wantDeps: yarnManyDeps,
		},
		{
			name:     "yarn real world",
			file:     "testdata/yarn_realworld.lock",
			want:     yarnRealWorld,
			wantDeps: yarnRealWorldDeps,
		},
		{
			file: "testdata/yarn_with_npm.lock",
			want: yarnWithNpm,
		},
		{
			name:     "yarn v2 normal",
			file:     "testdata/yarn_v2_normal.lock",
			want:     yarnV2Normal,
			wantDeps: yarnV2NormalDeps,
		},
		{
			name:     "yarn v2 react",
			file:     "testdata/yarn_v2_react.lock",
			want:     yarnV2React,
			wantDeps: yarnV2ReactDeps,
		},
		{
			name:     "yarn v2 with dev",
			file:     "testdata/yarn_v2_with_dev.lock",
			want:     yarnV2WithDev,
			wantDeps: yarnV2WithDevDeps,
		},
		{
			name:     "yarn v2 many",
			file:     "testdata/yarn_v2_many.lock",
			want:     yarnV2Many,
			wantDeps: yarnV2ManyDeps,
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
	sort.Slice(libs, func(i, j int) bool {
		ret := strings.Compare(libs[i].Name, libs[j].Name)
		if ret == 0 {
			return libs[i].Version < libs[j].Version
		}
		return ret < 0
	})
	for _, lib := range libs {
		sortLocations(lib.Locations)
	}
}

func sortLocations(locs []types.Location) {
	sort.Slice(locs, func(i, j int) bool {
		return locs[i].StartLine < locs[j].StartLine
	})
}
