package egg

import (
	"os"
	"path"
	"testing"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file string // Test input file
		want []types.Library
	}{
		{
			file: "testdata/setuptools-51.3.3-py3.8.egg-info.PKG-INFO",

			// docker run --name python --rm -it python:3.9-alpine sh
			// apk add py3-setuptools
			// cat /usr/lib/python3.8/site-packages/setuptools-51.3.3-py3.8.egg-info/PKG-INFO | awk  '/^Name:|^Version:|^License:/{print}' | tr -d '\n' |    \
			// sed "s/Name: /\n/g" | sed "s/Version: /:/g" | sed  "s/License: /:/g" | sed '1d' |  \
			// awk '{split($0,a,":"); printf("{\"%s\", \"%s\", \"%s\"}\n", a[1], a[2], a[3])}'
			want: []types.Library{
				{"setuptools", "51.3.3", "UNKNOWN"},
			},
		},
		{
			file: "testdata/six-1.15.0-py3.8.egg-info",

			// docker run --name python --rm -it python:3.9-alpine sh
			// apk add py3-setuptools
			// cat /usr/lib/python3.8/site-packages/six-1.15.0-py3.8.egg-info | awk  '/^Name:|^Version:|^License:/{print}' | tr -d '\n' |    \
			// sed "s/Name: /\n/g" | sed "s/Version: /:/g" | sed  "s/License: /:/g" | sed '1d' |  \
			// awk '{split($0,a,":"); printf("{\"%s\", \"%s\", \"%s\"}\n", a[1], a[2], a[3])}'
			want: []types.Library{
				{"six", "1.15.0", "MIT"},
			},
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, err := Parse(f)
			require.NoError(t, err)

			assert.Equal(t, v.want, got)
		})
	}
}
