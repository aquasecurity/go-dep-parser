package packagejson_test

import (
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		name      string
		inputFile string
		want      packagejson.Package
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/package.json",

			// docker run --name composer --rm -it node:12-alpine sh
			// npm init --force
			// npm install --save promise jquery
			// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
			want: packagejson.Package{
				Library: types.Library{
					ID:      "bootstrap@5.0.2",
					Name:    "bootstrap",
					Version: "5.0.2",
					License: "MIT",
				},
				Dependencies: map[string]string{
					"js-tokens": "^4.0.0",
				},
				OptionalDependencies: map[string]string{
					"colors": "^1.4.0",
				},
			},
		},
		{
			name:      "happy path - legacy license",
			inputFile: "testdata/legacy_package.json",
			want: packagejson.Package{
				Library: types.Library{
					ID:      "angular@4.1.2",
					Name:    "angular",
					Version: "4.1.2",
					License: "ISC",
				},
				Dependencies: map[string]string{},
			},
		},
		{
			name:      "happy path - version doesn't exist",
			inputFile: "testdata/without_version_package.json",
			want: packagejson.Package{
				Library: types.Library{
					ID:   "angular@",
					Name: "angular",
				},
			},
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
		{
			name:      "without name and version",
			inputFile: "testdata/without_name_and_version_package.json",
			want: packagejson.Package{
				Library: types.Library{
					ID:      "mypackage-2023-06-16T03:03:03Z@",
					Name:    "mypackage-2023-06-16T03:03:03Z",
					License: "MIT",
				},
			},
		},
		{
			name:      "empty package",
			inputFile: "testdata/empty_package.json",
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.name), func(t *testing.T) {
			f, err := os.Open(v.inputFile)
			require.NoError(t, err)
			defer f.Close()

			now := func() time.Time {
				return time.Date(2023, 06, 16, 3, 3, 3, 0, time.UTC)
			}

			got, err := packagejson.NewParser(packagejson.WithNow(now)).Parse(f)
			if v.wantErr != "" {
				assert.ErrorContains(t, err, v.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, v.want, got)
		})
	}
}
