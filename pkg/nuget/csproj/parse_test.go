package csproj_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/nuget/csproj"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string // Test input file
		inputFile string
		want      []types.Library
		wantErr   string
	}{
		{
			name:      "csproj",
			inputFile: "testdata/packages.csproj",
			want: []types.Library{
				{Name: "Newtonsoft.Json", Version: "6.0.4"},
				{Name: "Microsoft.AspNet.WebApi", Version: "5.2.2"},
				{Name: "Floating.Version", Version: "1.2"},
			},
		},
		{
			name:      "with development dependency",
			inputFile: "testdata/dev_dependency.csproj",
			want: []types.Library{
				{Name: "PrivateAssets.Tag.None", Version: "1.0.0"},
				{Name: "PrivateAssets.Conflicting.Tag.Attribute", Version: "1.0.0"},
				{Name: "ExcludeAssets.Tag.ContentFiles", Version: "1.0.0"},
				{Name: "ExcludeAssets.Tag.None", Version: "1.0.0"},
				{Name: "ExcludeAssets.Conflicting.Tag.Attribute", Version: "1.0.0"},
				{Name: "Newtonsoft.Json", Version: "8.0.3"},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/malformed_xml.csproj",
			wantErr:   "failed to decode .csproj file: XML syntax error on line 11: unexpected EOF",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			got, _, err := csproj.NewParser().Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}
