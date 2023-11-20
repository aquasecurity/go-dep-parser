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

func TestParsePattern(t *testing.T) {
	vectors := []struct {
		name           string
		target         string
		expectName     string
		expectProtocol string
		expactVersion  string
		occurErr       bool
	}{
		{
			name:          "normal",
			target:        `asn1@~0.2.3:`,
			expectName:    "asn1",
			expactVersion: "~0.2.3",
		},
		{
			name:           "normal with protocol",
			target:         `asn1@npm:~0.2.3:`,
			expectName:     "asn1",
			expectProtocol: "npm",
			expactVersion:  "~0.2.3",
		},
		{
			name:          "scope",
			target:        `@babel/code-frame@^7.0.0:`,
			expectName:    "@babel/code-frame",
			expactVersion: "^7.0.0",
		},
		{
			name:           "scope with protocol",
			target:         `@babel/code-frame@npm:^7.0.0:`,
			expectName:     "@babel/code-frame",
			expectProtocol: "npm",
			expactVersion:  "^7.0.0",
		},
		{
			name:           "scope with protocol and quotes",
			target:         `"@babel/code-frame@npm:^7.0.0":`,
			expectName:     "@babel/code-frame",
			expectProtocol: "npm",
			expactVersion:  "^7.0.0",
		},
		{
			name:          "unusual version",
			target:        `grunt-contrib-cssmin@3.0.*:`,
			expectName:    "grunt-contrib-cssmin",
			expactVersion: "3.0.*",
		},
		{
			name:          "conditional version",
			target:        `"js-tokens@^3.0.0 || ^4.0.0":`,
			expectName:    "js-tokens",
			expactVersion: "^3.0.0 || ^4.0.0",
		},
		{
			target:        "grunt-contrib-uglify-es@gruntjs/grunt-contrib-uglify#harmony:",
			expectName:    "grunt-contrib-uglify-es",
			expactVersion: "gruntjs/grunt-contrib-uglify#harmony",
		},
		{
			target:         `"jquery@git+https://xxxx:x-oauth-basic@github.com/tomoyamachi/jquery":`,
			expectName:     "jquery",
			expectProtocol: "git+https",
			expactVersion:  "//xxxx:x-oauth-basic@github.com/tomoyamachi/jquery",
		},
		{
			target:   `normal line`,
			occurErr: true,
		},
	}

	for _, v := range vectors {
		gotName, gotProtocol, gotVersion, err := parsePattern(v.target)

		if v.occurErr != (err != nil) {
			t.Errorf("expect error %t but err is %s", v.occurErr, err)
			continue
		}

		if gotName != v.expectName {
			t.Errorf("name mismatch: got %s, want %s, target :%s", gotName, v.expectName, v.target)
		}

		if gotProtocol != v.expectProtocol {
			t.Errorf("protocol mismatch: got %s, want %s, target :%s", gotProtocol, v.expectProtocol, v.target)
		}

		if gotVersion != v.expactVersion {
			t.Errorf("version mismatch: got %s, want %s, target :%s", gotVersion, v.expactVersion, v.target)
		}
	}
}

func TestParsePackagePatterns(t *testing.T) {
	vectors := []struct {
		name           string
		target         string
		expectName     string
		expectProtocol string
		expactPatterns []string
		occurErr       bool
	}{
		{
			name:       "normal",
			target:     `asn1@~0.2.3:`,
			expectName: "asn1",
			expactPatterns: []string{
				"asn1@~0.2.3",
			},
		},
		{
			name:       "normal with quotes",
			target:     `"asn1@~0.2.3":`,
			expectName: "asn1",
			expactPatterns: []string{
				"asn1@~0.2.3",
			},
		},
		{
			name:           "normal with protocol",
			target:         `asn1@npm:~0.2.3:`,
			expectName:     "asn1",
			expectProtocol: "npm",
			expactPatterns: []string{
				"asn1@~0.2.3",
			},
		},
		{
			name:       "multiple patterns",
			target:     `loose-envify@^1.1.0, loose-envify@^1.4.0:`,
			expectName: "loose-envify",
			expactPatterns: []string{
				"loose-envify@^1.1.0",
				"loose-envify@^1.4.0",
			},
		},
		{
			name:           "multiple patterns v2",
			target:         `"loose-envify@npm:^1.1.0, loose-envify@npm:^1.4.0":`,
			expectName:     "loose-envify",
			expectProtocol: "npm",
			expactPatterns: []string{
				"loose-envify@^1.1.0",
				"loose-envify@^1.4.0",
			},
		},
		{
			target:   `normal line`,
			occurErr: true,
		},
	}

	for _, v := range vectors {
		gotName, gotProtocol, gotPatterns, err := parsePackagePatterns(v.target)

		if v.occurErr != (err != nil) {
			t.Errorf("expect error %t but err is %s", v.occurErr, err)
			continue
		}

		if gotName != v.expectName {
			t.Errorf("name mismatch: got %s, want %s, target: %s", gotName, v.expectName, v.target)
		}

		if gotProtocol != v.expectProtocol {
			t.Errorf("protocol mismatch: got %s, want %s, target: %s", gotProtocol, v.expectProtocol, v.target)
		}

		sort.Strings(gotPatterns)
		sort.Strings(v.expactPatterns)

		assert.Equal(t, v.expactPatterns, gotPatterns)
	}
}

func TestGetDependency(t *testing.T) {
	vectors := []struct {
		name          string
		target        string
		expectName    string
		expactVersion string
		occurErr      bool
	}{
		{
			name:          "normal",
			target:        `    chalk "^2.0.1"`,
			expectName:    "chalk",
			expactVersion: "^2.0.1",
		},
		{
			name:          "range",
			target:        `    js-tokens "^3.0.0 || ^4.0.0"`,
			expectName:    "js-tokens",
			expactVersion: "^3.0.0 || ^4.0.0",
		},
		{
			name:          "normal v2",
			target:        `    depd: ~1.1.2`,
			expectName:    "depd",
			expactVersion: "~1.1.2",
		},
		{
			name:          "range version v2",
			target:        `    statuses: ">= 1.5.0 < 2"`,
			expectName:    "statuses",
			expactVersion: ">= 1.5.0 < 2",
		},
		{
			name:          "name with scope",
			target:        `    "@types/color-name": ^1.1.1`,
			expectName:    "@types/color-name",
			expactVersion: "^1.1.1",
		},
		{
			name:          "version with protocol",
			target:        `    ms: "npm:2.1.2"`,
			expectName:    "ms",
			expactVersion: "2.1.2",
		},
		{
			name:          "version with ignore protocol",
			target:        `    ms: "git:2.1.2"`,
			expectName:    "",
			expactVersion: "",
		},
	}

	for _, v := range vectors {
		gotName, gotVersion, err := getDependency(v.target)

		if v.occurErr != (err != nil) {
			t.Errorf("expect error %t but err is %s", v.occurErr, err)
			continue
		}

		if gotName != v.expectName {
			t.Errorf("name mismatch: got %s, want %s, target: %s", gotName, v.expectName, v.target)
		}

		if gotVersion != v.expactVersion {
			t.Errorf("version mismatch: got %s, want %s, target: %s", gotVersion, v.expactVersion, v.target)
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
			name: "yarn with npm",
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
		{
			name:     "yarn v2 with dependenciesMeta",
			file:     "testdata/yarn_v2_with_depsMeta.lock",
			want:     yarnV2WithDependenciesMeta,
			wantDeps: yarnV2WithDependenciesMetaDeps,
		},
		{
			name:     "yarn with local dependency",
			file:     "testdata/yarn_with_local.lock",
			want:     yarnNormal,
			wantDeps: yarnNormalDeps,
		},
		{
			name: "yarn with git dependency",
			file: "testdata/yarn_with_git.lock",
		},
		{
			name: "yarn file with bad protocol",
			file: "testdata/yarn_with_bad_protocol.lock",
			want: yarnBadProtocol,
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
