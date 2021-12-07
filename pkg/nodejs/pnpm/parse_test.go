package pnpm

import (
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file string
		want []types.Library
	}{
		{
			file: "testdata/pnpm-lock-normal.yaml",
			want: pnpmNormal,
		},
		{
			file: "testdata/pnpm-lock-react.yaml",
			want: pnpmReact,
		},
		{
			file: "testdata/pnpm-lock-many.yaml",
			want: pnpmMany,
		},
		{
			file: "testdata/pnpm-lock-manyv2.yaml",
			want: pnpmManyV2,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, err := Parse(f)
			require.NoError(t, err)

			sortLibs(got)
			sortLibs(v.want)

			assert.Equal(t, v.want, got)
		})
	}
}

func sortLibs(libs []types.Library) {
	sort.Slice(libs, func(i, j int) bool {
		ret := strings.Compare(libs[i].Name, libs[j].Name)
		if ret == 0 {
			return libs[i].Version < libs[j].Version
		}
		return ret < 0
	})
}
