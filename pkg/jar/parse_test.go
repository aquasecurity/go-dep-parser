package jar

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
		file string // Test input file
		want []types.Library
	}{
		{
			file: "testdata/maven.war",
			want: jarMaven,
		},
		{
			file: "testdata/gradle.war",
			want: jarGradle,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
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
