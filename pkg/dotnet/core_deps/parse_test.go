package core_deps

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
		file     string // Test input file
		wantLibs []types.Library
		wantDeps []types.Dependency
		wantErr  string
	}{
		{
			file: "testdata/MyExample.deps.json",
			wantLibs: []types.Library{
				{ID: "MyWebApp/1.0.0", Name: "MyWebApp", Version: "1.0.0", Locations: []types.Location{{StartLine: 9, EndLine: 16}}},
				{ID: "Microsoft.Extensions.Configuration.Abstractions/2.2.0", Name: "Microsoft.Extensions.Configuration.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 17, EndLine: 21}}},
				{ID: "Microsoft.Extensions.DependencyInjection.Abstractions/2.2.0", Name: "Microsoft.Extensions.DependencyInjection.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 22, EndLine: 22}}},
				{ID: "Microsoft.Extensions.FileProviders.Abstractions/2.2.0", Name: "Microsoft.Extensions.FileProviders.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 23, EndLine: 27}}},
				{ID: "Microsoft.Extensions.Hosting.Abstractions/2.2.0", Name: "Microsoft.Extensions.Hosting.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 28, EndLine: 35}}},
				{ID: "Microsoft.Extensions.Logging.Abstractions/2.2.0", Name: "Microsoft.Extensions.Logging.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 36, EndLine: 36}}},
				{ID: "Microsoft.Extensions.Primitives/2.2.0", Name: "Microsoft.Extensions.Primitives", Version: "2.2.0", Locations: []types.Location{{StartLine: 37, EndLine: 42}}},
				{ID: "System.Memory/4.5.1", Name: "System.Memory", Version: "4.5.1", Locations: []types.Location{{StartLine: 43, EndLine: 43}}},
				{ID: "System.Runtime.CompilerServices.Unsafe/4.5.1", Name: "System.Runtime.CompilerServices.Unsafe", Version: "4.5.1", Locations: []types.Location{{StartLine: 44, EndLine: 44}}},
			},
			wantDeps: []types.Dependency{
				{
					ID: "MyWebApp/1.0.0",
					DependsOn: []string{
						"Microsoft.Extensions.Hosting.Abstractions/2.2.0",
					},
				},
				{
					ID: "Microsoft.Extensions.Hosting.Abstractions/2.2.0",
					DependsOn: []string{
						"Microsoft.Extensions.Configuration.Abstractions/2.2.0",
						"Microsoft.Extensions.DependencyInjection.Abstractions/2.2.0",
						"Microsoft.Extensions.FileProviders.Abstractions/2.2.0",
						"Microsoft.Extensions.Logging.Abstractions/2.2.0",
					},
				},
				{
					ID: "Microsoft.Extensions.Configuration.Abstractions/2.2.0",
					DependsOn: []string{
						"Microsoft.Extensions.Primitives/2.2.0",
					},
				},
				{
					ID: "Microsoft.Extensions.FileProviders.Abstractions/2.2.0",
					DependsOn: []string{
						"Microsoft.Extensions.Primitives/2.2.0",
					},
				},
				{
					ID: "Microsoft.Extensions.Primitives/2.2.0",
					DependsOn: []string{
						"System.Memory/4.5.1",
						"System.Runtime.CompilerServices.Unsafe/4.5.1",
					},
				},
			},
		},

		{
			file: "testdata/ExampleApp1.deps.json",
			wantLibs: []types.Library{
				{ID: "Newtonsoft.Json/13.0.1", Name: "Newtonsoft.Json", Version: "13.0.1", Locations: []types.Location{{StartLine: 17, EndLine: 24}}},
				{ID: "ExampleApp1/1.0.0", Name: "ExampleApp1", Version: "1.0.0", Locations: []types.Location{{StartLine: 9, EndLine: 16}}},
			},
			wantDeps: []types.Dependency{
				{ID: "ExampleApp1/1.0.0", DependsOn: []string{"Newtonsoft.Json/13.0.1"}},
			},
		},
		{
			file: "testdata/NoLibraries.deps.json",
			wantLibs: []types.Library{
				{ID: "ExampleApp1/1.0.0", Name: "ExampleApp1", Version: "1.0.0", Locations: types.Locations{types.Location{StartLine: 9, EndLine: 16}}},
				{ID: "Newtonsoft.Json/13.0.1", Name: "Newtonsoft.Json", Version: "13.0.1", Locations: types.Locations{types.Location{StartLine: 17, EndLine: 24}}},
			},
			wantDeps: []types.Dependency{
				{ID: "ExampleApp1/1.0.0", DependsOn: []string{"Newtonsoft.Json/13.0.1"}},
			},
		},
		{
			file:    "testdata/InvalidJson.deps.json",
			wantErr: "failed to decode .deps.json file: EOF",
		},
	}

	for _, tt := range vectors {
		t.Run(path.Base(tt.file), func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			gotLibs, gotDeps, err := NewParser().Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)

				sort.Slice(gotLibs, func(i, j int) bool {
					ret := strings.Compare(gotLibs[i].Name, gotLibs[j].Name)
					if ret == 0 {
						return gotLibs[i].Version < gotLibs[j].Version
					}
					return ret < 0
				})

				sort.Slice(gotDeps, func(i, j int) bool {
					return gotDeps[i].ID < gotDeps[j].ID
				})

				for _, dep := range gotDeps {
					sort.Strings(dep.DependsOn)
				}

				sort.Slice(tt.wantLibs, func(i, j int) bool {
					ret := strings.Compare(tt.wantLibs[i].Name, tt.wantLibs[j].Name)
					if ret == 0 {
						return tt.wantLibs[i].Version < tt.wantLibs[j].Version
					}
					return ret < 0
				})

				sort.Slice(tt.wantDeps, func(i, j int) bool {
					return tt.wantDeps[i].ID < tt.wantDeps[j].ID
				})

				for _, dep := range tt.wantDeps {
					sort.Strings(dep.DependsOn)
				}

				assert.Equal(t, tt.wantLibs, gotLibs)
				assert.Equal(t, tt.wantDeps, gotDeps)
			}
		})
	}
}
