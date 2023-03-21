package packagejson_test

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		name      string
		inputFile string
		want      types.Library
		wantDeps  map[string]string
		wantErr   string
	}{
		{
			name:      "happypath",
			inputFile: "testdata/package.json",

			// docker run --name composer --rm -it node:12-alpine sh
			// npm init --force
			// npm install --save promise jquery
			// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
			want: types.Library{
				ID:      "bootstrap@5.0.2",
				Name:    "bootstrap",
				Version: "5.0.2",
				License: "MIT",
			},
			wantDeps: map[string]string{
				"js-tokens": "^4.0.0",
			},
		},
		{
			name:      "happy path - legacy license",
			inputFile: "testdata/legacy_package.json",
			want: types.Library{
				ID:      "angular@4.1.2",
				Name:    "angular",
				Version: "4.1.2",
				License: "ISC",
			},
			wantDeps: map[string]string{},
		},
		{
			name:      "sad path",
			inputFile: "testdata/invalid_package.json",

			// docker run --name composer --rm -it node:12-alpine sh
			// npm init --force
			// npm install --save promise jquery
			// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
			wantErr: "JSON decode error",
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.name), func(t *testing.T) {
			f, err := os.Open(v.inputFile)
			require.NoError(t, err)
			defer f.Close()

			got, gotDeps, err := packagejson.NewParser().Parse(f)
			if v.wantErr != "" {
				assert.ErrorContains(t, err, v.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, v.want, got)
			assert.Equal(t, v.wantDeps, gotDeps)
		})
	}
}
