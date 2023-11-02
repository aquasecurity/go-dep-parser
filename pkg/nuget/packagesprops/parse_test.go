package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	config "github.com/aquasecurity/go-dep-parser/pkg/nuget/packagesprops"
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
			name:      "PackagesProps",
			inputFile: "testdata/packages.props",
			want: []types.Library{
				{Name: "Microsoft.Extensions.Configuration", Version: "2.1.1"},
				{Name: "Microsoft.Extensions.DependencyInjection.Abstractions", Version: "2.2.1"},
				{Name: "Microsoft.Extensions.Http", Version: "3.2.1"},
			},
		},
		{
			name:      "DirectoryPackagesProps",
			inputFile: "testdata/Directory.Packages.props",
			want: []types.Library{
				{Name: "PackageOne", Version: "6.2.3"},
				{Name: "PackageTwo", Version: "6.0.0"},
				{Name: "PackageThree", Version: "2.4.1"},
			},
		},
		{
			name:      "NoItemGroupInXMLStructure",
			inputFile: "testdata/no_item_group.props",
			want:      []types.Library{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			got, _, err := config.NewParser().Parse(f)
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
