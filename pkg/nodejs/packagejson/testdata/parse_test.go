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
		file string // Test input file
		want types.Library
	}{
		{
			file: "package.json",

			// docker run --name composer --rm -it node:12-alpine sh
			// npm init --force
			// npm install --save promise jquery
			// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
			want: types.Library{
				Name:    "bootstrap",
				Version: "5.0.2",
				License: "MIT",
			},
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, err := packagejson.Parse(f)
			require.NoError(t, err)

			assert.Equal(t, v.want, got)
		})
	}
}

func Test_parseLicense(t *testing.T) {
	cases := []struct {
		name     string
		value    interface{}
		expected string
	}{
		{
			name:     "1 license",
			value:    "BSD-3-Clause",
			expected: "BSD-3-Clause",
		},
		{
			value: packagejson.LegacyLicense{
				Type: "MIT",
				Url:  "https://some-url.com",
			},
			expected: "MIT",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := packagejson.ParseLicense(c.value)
			assert.Equal(t, c.expected, got)
		})
	}
}
