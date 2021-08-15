package wordpress

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParseWordPress(t *testing.T) {
	tests := []struct {
		file    string // Test input file
		want    types.Library
		wantErr string
	}{
		{
			file:    "testdata/version.php",
			want:    types.Library{"wordpress", "4.9.4-alpha", ""},
			wantErr: "",
		},
		{
			file:    "testdata/versionFail.php",
			want:    *new(types.Library),
			wantErr: "version.php could not be parsed",
		},
	}

	for _, tt := range tests {
		t.Run(path.Base(tt.file), func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, err := Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
