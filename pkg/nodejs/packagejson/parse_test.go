package packagejson_test

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thoas/go-funk"

	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		name      string
		inputFile string
		want      []types.Library
		wantErr   string
	}{
		{
			name:      "happypath",
			inputFile: "testdata/package.json",

			// docker run --name composer --rm -it node:12-alpine sh
			// npm init --force
			// npm install --save promise jquery
			// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
			want: []types.Library{{
				Name:               "bootstrap",
				Version:            "5.0.2",
				License:            "MIT",
				ExternalReferences: []types.ExternalRef{{Type: types.Website, Url: "https://getbootstrap.com/"}, {Type: types.Vcs, Url: "git+https://github.com/twbs/bootstrap.git"}, {Type: types.IssueTracker, Url: "https://github.com/twbs/bootstrap/issues"}},
			}},
			wantErr: "",
		},
		{
			name:      "happy path - legacy license",
			inputFile: "testdata/legacy_package.json",
			want: []types.Library{{
				Name:               "angular",
				Version:            "4.1.2",
				License:            "ISC",
				ExternalReferences: []types.ExternalRef{{Type: types.Website, Url: "https://getbootstrap.com/"}, {Type: types.Vcs, Url: "git+https://github.com/twbs/bootstrap.git"}, {Type: types.IssueTracker, Url: "https://github.com/twbs/bootstrap/issues"}, {Type: types.License, Url: "https://opensource.org/licenses/ISC"}},
			}},
			wantErr: "",
		},
		{
			name:      "sad path",
			inputFile: "testdata/invalid_package.json",

			// docker run --name composer --rm -it node:12-alpine sh
			// npm init --force
			// npm install --save promise jquery
			// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
			want:    []types.Library{},
			wantErr: "JSON decode error",
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.name), func(t *testing.T) {
			f, err := os.Open(v.inputFile)
			require.NoError(t, err)

			got, _, err := packagejson.NewParser().Parse(f)
			if v.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), v.wantErr)
				return
			}

			require.NoError(t, err)
			comparableKeys := []string{"Name", "Version", "License"}
			inComparableKeys := []string{"ExternalReferences"}
			for _, key := range comparableKeys {
				expected := funk.Get(v.want, key)
				actual := funk.Get(got, key)
				assert.Equal(t, expected, actual)
			}

			for _, key := range inComparableKeys {
				expected := funk.Get(v.want, key)
				actual := funk.Get(got, key)
				assert.ElementsMatch(t, expected, actual)
			}
		})
	}
}
