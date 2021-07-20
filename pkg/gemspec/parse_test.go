package gemspec

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
		want []types.Library
	}{
		{
			file: "testdata/rubygems-update.gemspec",
			want: RubyGemUpdate,
		},
		{
			file: "testdata/binary_json-2.3.0.gemspec",
			want: nil,
		},
		{
			file: "testdata/json-java-name.gemspec",
			want: nil,
		},
		{
			file: "testdata/json-java.gemspec",
			want: nil,
		},
		{
			file: "testdata/json-2.3.0.gemspec",
			want: JsonGem,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, err := Parse(f, v.file)
			require.NoError(t, err)

			assert.Equal(t, v.want, got)
		})
	}
}
