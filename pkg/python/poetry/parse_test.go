package poetry

import (
	"os"
	"path"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file     string // Test input file
		wantLibs []types.Library
		wantDeps []types.Dependency
	}{
		{
			file:     "testdata/poetry_normal.lock",
			wantLibs: poetryNormal,
		},
		{
			file:     "testdata/poetry_many.lock",
			wantLibs: poetryMany,
			wantDeps: poetryManyDeps,
		},
		{
			file:     "testdata/poetry_flask.lock",
			wantLibs: poetryFlask,
			wantDeps: poetryFlaskDeps,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			gotLibs, gotDeps, err := NewParser().Parse(f)
			require.NoError(t, err)

			// check libs
			sort.Slice(gotLibs, func(i, j int) bool {
				return gotLibs[i].ID < gotLibs[j].ID
			})
			sort.Slice(v.wantLibs, func(i, j int) bool {
				return v.wantLibs[i].ID < v.wantLibs[j].ID
			})
			assert.Equal(t, v.wantLibs, gotLibs)

			// check deps
			sort.Slice(gotDeps, func(i, j int) bool {
				return gotDeps[i].ID < gotDeps[j].ID
			})
			sort.Slice(v.wantDeps, func(i, j int) bool {
				return v.wantDeps[i].ID < v.wantDeps[j].ID
			})
			assert.Equal(t, v.wantDeps, gotDeps)
		})
	}
}

func TestParseDependency(t *testing.T) {
	tests := []struct {
		name         string
		packageName  string
		versionRange interface{}
		libsVersions map[string][]string
		want         string
		wantErr      string
	}{
		{
			name:         "handle package name",
			packageName:  "Test_project.Name",
			versionRange: "*",
			libsVersions: map[string][]string{
				"test-project-name": {"1.0.0"},
			},
			want: "test-project-name@1.0.0",
		},
		{
			name:         "version range as string",
			packageName:  "test",
			versionRange: ">=1.0.0",
			libsVersions: map[string][]string{
				"test": {"2.0.0"},
			},
			want: "test@2.0.0",
		},
		{
			name:         "version range == *",
			packageName:  "test",
			versionRange: "*",
			libsVersions: map[string][]string{
				"test": {"3.0.0"},
			},
			want: "test@3.0.0",
		},
		{
			name:        "version range as json",
			packageName: "test",
			versionRange: map[string]interface{}{
				"version": ">=4.8.3",
				"markers": "python_version < \"3.8\"",
			},
			libsVersions: map[string][]string{
				"test": {"5.0.0"},
			},
			want: "test@5.0.0",
		},
		{
			name:         "libsVersions doesn't contain required version",
			packageName:  "test",
			versionRange: ">=1.0.0",
			libsVersions: map[string][]string{},
			wantErr:      "failed to find version for \"test\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDependency(tt.packageName, tt.versionRange, tt.libsVersions)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
