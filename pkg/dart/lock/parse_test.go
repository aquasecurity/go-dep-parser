package lock_test

import (
	"github.com/aquasecurity/go-dep-parser/pkg/dart/lock"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"sort"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		wantLibs  []types.Library
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.lock",
			wantLibs: []types.Library{
				{
					ID:      "crypto@3.0.2",
					Name:    "crypto",
					Version: "3.0.2",
				},
				{
					ID:      "flutter_test@0.0.0",
					Name:    "flutter_test",
					Version: "0.0.0",
				},
				{
					ID:       "uuid@3.0.6",
					Name:     "uuid",
					Version:  "3.0.6",
					Indirect: true,
				},
			},
		},
		{
			name:      "empty path",
			inputFile: "testdata/empty.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()
			gotLibs, _, err := lock.NewParser().Parse(f)
			require.NoError(t, err)

			sort.Slice(gotLibs, func(i, j int) bool {
				return gotLibs[i].ID < gotLibs[j].ID
			})

			assert.Equal(t, tt.wantLibs, gotLibs)
		})
	}
}
