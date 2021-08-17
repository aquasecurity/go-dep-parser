package gemspec

import (
	"os"
	"path"
	"testing"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file      string // Test input file
		libraries []types.Library
	}{
		{
			file:      "testdata/normal00.gemspec",
			libraries: GemspecNormal,
		},
		{
			file:      "testdata/normal01.gemspec",
			libraries: GemspecNormal,
		},
		{
			file:      "testdata/normal02.gemspec",
			libraries: GemspecNormal,
		},
		{
			file:      "testdata/malformed00.gemspec",
			libraries: GemspecMalformed,
		},
		{
			file:      "testdata/malformed01.gemspec",
			libraries: GemspecMalformed,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)
			libList, err := Parse(f)
			reruire.NoError(t, err)

			assert.Equal(t, v.want, got)
		})
	}
}
