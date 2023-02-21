package bundler

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file string // Test input file
		libs []types.Library
		deps []types.Dependency
	}{
		{
			file: "testdata/Gemfile_normal.lock",
			libs: BundlerNormal,
			deps: BundlerNormalDeps,
		},
		{
			file: "testdata/Gemfile_rails.lock",
			libs: BundlerRails,
			deps: BundlerRailsDeps,
		},
		{
			file: "testdata/Gemfile_many.lock",
			libs: BundlerMany,
			deps: BundlerManyDeps,
		},
		{
			file: "testdata/Gemfile_rails7.lock",
			libs: BundlerV2RailsV7,
			deps: BundlerV2RailsV7Deps,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			libs, deps, err := NewParser().Parse(f)
			require.NoError(t, err)

			assert.Equal(t, v.libs, libs)
			assert.Equal(t, v.deps, deps)
		})
	}
}
