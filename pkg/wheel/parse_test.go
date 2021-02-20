package wheel

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file string // Test input file
		want []types.Library
	}{
		{
			file: "testdata/wheel_normal",
			want: WheelNormal,
		},
		{
			file: "testdata/wheel_many",
			want: WheelMany,
		},
		{
			file: "testdata/wheel_django",
			want: WheelDjango,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)
			got, err := walk(f)
			require.NoError(t, err)

			assert.Equal(t, v.want, got)
		})
	}
}

// walk is a test helper to traverse directories and look for METADATA files
// given that Parse only parses METADATA, as traversing directories is done in fanal
func walk(r io.Reader) ([]types.Library, error) {
	var libs []types.Library
	f, _ := r.(*os.File)
	fi, err := os.Stat(f.Name())
	if err != nil {
		return nil, xerrors.Errorf("stat error: %w", err)
	}
	if !fi.IsDir() {
		return nil, xerrors.New("not os.Dir")
	}

	walker := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && filepath.Base(path) == "METADATA" {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			lib, err := Parse(f)
			if err != nil {
				return err
			}
			libs = append(libs, lib...)
		}
		return nil
	}

	return libs, filepath.Walk(f.Name(), walker)
}
