package lock

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string // Test input file
		want      []types.Library
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.lock",
			want: []types.Library{
				{
					Name:    "pkga",
					Version: "0.0.1",
				},
				{
					Name:    "pkgc",
					Version: "0.1.1",
				},
			},
		},
		{
			name:      "happy path. lock file without dependencies",
			inputFile: "testdata/empty.lock",
		},
		{
			name:      "sad path. wrong ref format",
			inputFile: "testdata/sad.lock",
			wantErr:   "unable to parse ref",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			got, _, err := NewParser().Parse(f)

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			sort.Slice(got, func(i, j int) bool {
				ret := strings.Compare(got[i].Name, got[j].Name)
				if ret == 0 {
					return got[i].Version < got[j].Version
				}
				return ret < 0
			})

			sort.Slice(tt.want, func(i, j int) bool {
				ret := strings.Compare(tt.want[i].Name, tt.want[j].Name)
				if ret == 0 {
					return tt.want[i].Version < tt.want[j].Version
				}
				return ret < 0
			})

			assert.Equal(t, tt.want, got)
		})
	}
}
