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
		want types.Library
	}{
		// listing dependencies based on */specifications/*gemspec
		// docker run --name rails --rm -it rails:latest /bin/sh
		// find / -wholename "*/specifications/*gemspec" | xargs -I {} sh -c 'cat {} | grep -e "s\.name " -e "s\.version " -e "s\.licenses "' | tee METADATAS
		// cat METADATAS | cut -d" " -f2- | tr "\n" "\t" | awk -F "\t" '{for(i=1;i<=NF;i=i+3){printf "\{\""$i"\", \""$(i+1)"\", \""$(i+2)"\"\}\n"}}'
		{
			file: "testdata/rubygems-update.gemspec",
			want: types.Library{"rubygems-update", "3.0.3", "2-clauseBSDL,Ruby"},
		},
		{
			file: "testdata/binary_json-2.3.0.gemspec",
			want: types.Library{},
		},
		{
			// If .gemspec is from source code.
			// It is not expected to be parsed.
			file: "testdata/net-ftp-0.1.1.gemspec",
			want: types.Library{},
		},
		{
			// If .gemspec is from source code.
			// It is not expected to be parsed.
			file: "testdata/matrix-0.3.1/local.gemspec",
			want: types.Library{},
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
