package nugetlock

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
		file string // Test input file
		want []types.Library
	}{
		{
			file: "testdata/packages_lock_simple.json",
			want: NuGetSimple,
		},
		{
			file: "testdata/packages_lock_subdependencies.json",
			want: NuGetSubDependencies,
		},
		{
			file: "testdata/packages_lock_multi.json",
			want: NuGetMultiTarget,
		},
		{
			file: "testdata/packages_lock_legacy.json",
			want: NuGetLegacy,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, err := Parse(f)
			require.NoError(t, err)

			sort.Slice(got, func(i, j int) bool {
				ret := strings.Compare(got[i].Name, got[j].Name)
				if ret == 0 {
					return got[i].Version < got[j].Version
				}
				return ret < 0
			})

			sort.Slice(v.want, func(i, j int) bool {
				ret := strings.Compare(v.want[i].Name, v.want[j].Name)
				if ret == 0 {
					return v.want[i].Version < v.want[j].Version
				}
				return ret < 0
			})

			assert.Equal(t, v.want, got)
		})
	}
}
