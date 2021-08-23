package packagejson

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
		{
			file: "testdata/package.json",

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

			got, err := Parse(f)
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
			name:     "OR seperated licenses",
			value:    "(LGPL-2.1 OR MIT OR BSD-3-Clause)",
			expected: "(LGPL-2.1 | MIT | BSD-3-Clause)",
		},
		{
			name:     "AND seperated licenses",
			value:    "(LGPL-2.1 AND MIT AND BSD-2-Clause)",
			expected: "(LGPL-2.1, MIT, BSD-2-Clause)",
		},
		{
			name:     "with exception license",
			value:    "(GPL-2.0+ WITH Bison-exception-2.2)",
			expected: "(GPL-2.0+ with Bison-exception-2.2)",
		},
		{
			name:     "composite licenses",
			value:    "(MIT AND (LGPL-2.1+ OR BSD-3-Clause))",
			expected: "(MIT, (LGPL-2.1+ | BSD-3-Clause))",
		},
		{
			value:    "SEE LICENSE IN <filename>",
			expected: "<filename>",
		},
		{
			value: legacyLicense{
				Type: "MIT",
				Url:  "https://some-url.com",
			},
			expected: "MIT",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseLicense(c.value)
			assert.Equal(t, c.expected, got)
		})
	}
}

func TestParsePkgJson(t *testing.T) {
	vectors := []struct {
		file string // Test input file
		want types.Library
	}{
		{
			file: "testdata/package.json",
			want: types.Library{"bootstrap", "5.0.2", "MIT"},
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
