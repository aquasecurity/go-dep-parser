package kas

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
		file string
		want []types.Library
	}{
		{
			file: "testdata/kas.yml",
			want: kasRepo,
		},
		{
			file: "testdata/kas-no-refspec.yml",
			want: kasRepoLatest,
		},
		{
			file: "testdata/kas-git-url.yml",
			want: kasRepoGitUrl,
		},
		{
			file: "testdata/kas-git-url.yml",
			want: kasRepoSshUrl,
		},
		{
			file: "testdata/kas-multiple-repos.yml",
			want: kasRepos,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, _, err := NewParser().Parse(f)
			require.NoError(t, err)

			assert.Equal(t, v.want, got)
		})
	}
}
