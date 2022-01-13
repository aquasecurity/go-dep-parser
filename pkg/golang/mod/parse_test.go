package mod

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
	vectors := []struct {
		file string
		want []types.Library
	}{
		{
			file: "testdata/normal/go.mod",
			want: GoModNormal,
		},
		{
			file: "testdata/replaced/go.mod",
			want: GoModReplaced,
		},
		{
			file: "testdata/replaced-with-version/go.mod",
			want: GoModReplacedWithVersion,
		},
		{
			file: "testdata/replaced-with-version-mismatch/go.mod",
			want: GoModReplacedWithVersionMismatch,
		},
		{
			file: "testdata/replaced-with-local-path/go.mod",
			want: GoModReplacedWithLocalPath,
		},
		{
			file: "testdata/replaced-with-local-path-and-version/go.mod",
			want: GoModReplacedWithLocalPathAndVersion,
		},
		{
			file: "testdata/replaced-with-local-path-and-version-mismatch/go.mod",
			want: GoModReplacedWithLocalPathAndVersionMismatch,
		},
	}

	for _, v := range vectors {
		t.Run(strings.TrimPrefix(strings.TrimSuffix(v.file, "/go.mod"), "testdata/"), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, err := Parse(f)
			require.NoError(t, err)

			sort.Slice(got, func(i, j int) bool {
				return got[i].Name < got[j].Name
			})
			sort.Slice(v.want, func(i, j int) bool {
				return v.want[i].Name < v.want[j].Name
			})

			assert.Equal(t, v.want, got)
		})
	}
}
