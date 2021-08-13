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
	emptyLib := *new(types.Library)
	vectors := []struct {
		file string // Test input file
		want types.Library
	}{
		{
			file: "testdata/rubygems-update.gemspec",
			want: types.Library{"rubygems-update", "3.0.3", "2-clauseBSDL,Ruby"},
		},
		{
			file: "testdata/binary_json-2.3.0.gemspec",
			want: emptyLib,
		},
		{
			file: "testdata/net-ftp-0.1.1.gemspec",
			want: types.Library{"net-ftp", "0.1.1", "Ruby"},
		},
		{
			file: "testdata/matrix-0.3.1/local.gemspec",
			want: types.Library{"matrix", "0.3.1", "Ruby"},
		},
		{
			file: "testdata/json-2.3.0.gemspec",
			want: types.Library{"json", "2.3.0", "Ruby"},
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
