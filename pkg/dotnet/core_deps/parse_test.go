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
				{ID: "MyWebApp@1.0.0", Name: "MyWebApp", Version: "1.0.0", Locations: []types.Location{{StartLine: 148, EndLine: 152}}},
				{ID: "Microsoft.AspNetCore.Server.IIS@2.2.6", Name: "Microsoft.AspNetCore.Server.IIS", Version: "2.2.6", Locations: []types.Location{{StartLine: 216, EndLine: 222}}},
				{ID: "Microsoft.AspNetCore.Authentication.Abstractions@2.2.0", Name: "Microsoft.AspNetCore.Authentication.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 153, EndLine: 159}}},
				{ID: "Microsoft.AspNetCore.Authentication.Core@2.2.0", Name: "Microsoft.AspNetCore.Authentication.Core", Version: "2.2.0", Locations: []types.Location{{StartLine: 160, EndLine: 166}}},
				{ID: "Microsoft.AspNetCore.Connections.Abstractions@2.2.0", Name: "Microsoft.AspNetCore.Connections.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 167, EndLine: 173}}},
				{ID: "Microsoft.AspNetCore.Hosting.Abstractions@2.2.0", Name: "Microsoft.AspNetCore.Hosting.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 174, EndLine: 180}}},
				{ID: "Microsoft.AspNetCore.Hosting.Server.Abstractions@2.2.0", Name: "Microsoft.AspNetCore.Hosting.Server.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 181, EndLine: 187}}},
				{ID: "Microsoft.AspNetCore.Http@2.2.0", Name: "Microsoft.AspNetCore.Http", Version: "2.2.0", Locations: []types.Location{{StartLine: 188, EndLine: 194}}},
				{ID: "Microsoft.AspNetCore.Http.Abstractions@2.2.0", Name: "Microsoft.AspNetCore.Http.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 195, EndLine: 201}}},
				{ID: "Microsoft.AspNetCore.Http.Extensions@2.2.0", Name: "Microsoft.AspNetCore.Http.Extensions", Version: "2.2.0", Locations: []types.Location{{StartLine: 202, EndLine: 208}}},
				{ID: "Microsoft.AspNetCore.Http.Features@2.2.0", Name: "Microsoft.AspNetCore.Http.Features", Version: "2.2.0", Locations: []types.Location{{StartLine: 209, EndLine: 215}}},
				{ID: "Microsoft.AspNetCore.WebUtilities@2.2.0", Name: "Microsoft.AspNetCore.WebUtilities", Version: "2.2.0", Locations: []types.Location{{StartLine: 223, EndLine: 229}}},
				{ID: "Microsoft.Extensions.Configuration.Abstractions@2.2.0", Name: "Microsoft.Extensions.Configuration.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 230, EndLine: 236}}},
				{ID: "Microsoft.Extensions.DependencyInjection.Abstractions@2.2.0", Name: "Microsoft.Extensions.DependencyInjection.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 237, EndLine: 243}}},
				{ID: "Microsoft.Extensions.FileProviders.Abstractions@2.2.0", Name: "Microsoft.Extensions.FileProviders.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 244, EndLine: 250}}},
				{ID: "Microsoft.Extensions.Hosting.Abstractions@2.2.0", Name: "Microsoft.Extensions.Hosting.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 251, EndLine: 257}}},
				{ID: "Microsoft.Extensions.Logging.Abstractions@2.2.0", Name: "Microsoft.Extensions.Logging.Abstractions", Version: "2.2.0", Locations: []types.Location{{StartLine: 258, EndLine: 264}}},
				{ID: "Microsoft.Extensions.ObjectPool@2.2.0", Name: "Microsoft.Extensions.ObjectPool", Version: "2.2.0", Locations: []types.Location{{StartLine: 265, EndLine: 271}}},
				{ID: "Microsoft.Extensions.Options@2.2.0", Name: "Microsoft.Extensions.Options", Version: "2.2.0", Locations: []types.Location{{StartLine: 272, EndLine: 278}}},
				{ID: "Microsoft.Extensions.Primitives@2.2.0", Name: "Microsoft.Extensions.Primitives", Version: "2.2.0", Locations: []types.Location{{StartLine: 279, EndLine: 285}}},
				{ID: "Microsoft.Net.Http.Headers@2.2.0", Name: "Microsoft.Net.Http.Headers", Version: "2.2.0", Locations: []types.Location{{StartLine: 286, EndLine: 292}}},
				{ID: "Microsoft.NETCore.Platforms@2.0.0", Name: "Microsoft.NETCore.Platforms", Version: "2.0.0", Locations: []types.Location{{StartLine: 293, EndLine: 299}}},
				{ID: "System.Buffers@4.5.0", Name: "System.Buffers", Version: "4.5.0", Locations: []types.Location{{StartLine: 300, EndLine: 306}}},
				{ID: "System.ComponentModel.Annotations@4.5.0", Name: "System.ComponentModel.Annotations", Version: "4.5.0", Locations: []types.Location{{StartLine: 307, EndLine: 313}}},
				{ID: "System.IO.Pipelines@4.5.3", Name: "System.IO.Pipelines", Version: "4.5.3", Locations: []types.Location{{StartLine: 314, EndLine: 320}}},
				{ID: "System.Memory@4.5.1", Name: "System.Memory", Version: "4.5.1", Locations: []types.Location{{StartLine: 321, EndLine: 327}}},
				{ID: "System.Runtime.CompilerServices.Unsafe@4.5.1", Name: "System.Runtime.CompilerServices.Unsafe", Version: "4.5.1", Locations: []types.Location{{StartLine: 328, EndLine: 334}}},
				{ID: "System.Security.Principal.Windows@4.5.0", Name: "System.Security.Principal.Windows", Version: "4.5.0", Locations: []types.Location{{StartLine: 335, EndLine: 341}}},
				{ID: "System.Text.Encodings.Web@4.5.0", Name: "System.Text.Encodings.Web", Version: "4.5.0", Locations: []types.Location{{StartLine: 342, EndLine: 348}}},
			},
			wantDeps: []types.Dependency{
				{
					ID: "MyWebApp@1.0.0",
					DependsOn: []string{
						"Microsoft.AspNetCore.Server.IIS@2.2.6",
					},
				},
				{
					ID: "Microsoft.AspNetCore.Authentication.Abstractions@2.2.0",
					DependsOn: []string{
						"Microsoft.AspNetCore.Http.Abstractions@2.2.0",
						"Microsoft.Extensions.Logging.Abstractions@2.2.0",
						"Microsoft.Extensions.Options@2.2.0",
					},
				},
				{
					ID: "Microsoft.AspNetCore.Http.Extensions@2.2.0",
					DependsOn: []string{
						"Microsoft.AspNetCore.Http.Abstractions@2.2.0",
						"Microsoft.Extensions.FileProviders.Abstractions@2.2.0",
						"Microsoft.Net.Http.Headers@2.2.0",
						"System.Buffers@4.5.0",
					},
				},
				{
					ID: "Microsoft.AspNetCore.Authentication.Core@2.2.0",
					DependsOn: []string{
						"Microsoft.AspNetCore.Authentication.Abstractions@2.2.0",
						"Microsoft.AspNetCore.Http@2.2.0",
						"Microsoft.AspNetCore.Http.Extensions@2.2.0",
					},
				},
				{
					ID: "Microsoft.AspNetCore.Connections.Abstractions@2.2.0",
					DependsOn: []string{
						"Microsoft.AspNetCore.Http.Features@2.2.0",
						"System.IO.Pipelines@4.5.3",
					},
				},
				{
					ID: "Microsoft.AspNetCore.Hosting.Abstractions@2.2.0",
					DependsOn: []string{
						"Microsoft.AspNetCore.Hosting.Server.Abstractions@2.2.0",
						"Microsoft.AspNetCore.Http.Abstractions@2.2.0",
						"Microsoft.Extensions.Hosting.Abstractions@2.2.0",
					},
				},
				{
					ID: "Microsoft.AspNetCore.Http.Abstractions@2.2.0",
					DependsOn: []string{
						"Microsoft.AspNetCore.Http.Features@2.2.0",
						"System.Text.Encodings.Web@4.5.0",
					},
				},
				{
					ID: "Microsoft.AspNetCore.Hosting.Server.Abstractions@2.2.0",
					DependsOn: []string{
						"Microsoft.AspNetCore.Http.Features@2.2.0",
						"Microsoft.Extensions.Configuration.Abstractions@2.2.0",
					},
				},
				{
					ID: "Microsoft.AspNetCore.Http@2.2.0",
					DependsOn: []string{
						"Microsoft.AspNetCore.Http.Abstractions@2.2.0",
						"Microsoft.AspNetCore.WebUtilities@2.2.0",
						"Microsoft.Extensions.ObjectPool@2.2.0",
						"Microsoft.Extensions.Options@2.2.0",
						"Microsoft.Net.Http.Headers@2.2.0",
					},
				},
				{
					ID: "Microsoft.AspNetCore.Http.Features@2.2.0",
					DependsOn: []string{
						"Microsoft.Extensions.Primitives@2.2.0",
					},
				},
				{
					ID: "Microsoft.AspNetCore.Server.IIS@2.2.6",
					DependsOn: []string{
						"Microsoft.AspNetCore.Authentication.Core@2.2.0",
						"Microsoft.AspNetCore.Connections.Abstractions@2.2.0",
						"Microsoft.AspNetCore.Hosting.Abstractions@2.2.0",
						"System.IO.Pipelines@4.5.3",
						"System.Security.Principal.Windows@4.5.0",
					},
				},
				{
					ID: "Microsoft.AspNetCore.WebUtilities@2.2.0",
					DependsOn: []string{
						"Microsoft.Net.Http.Headers@2.2.0",
						"System.Text.Encodings.Web@4.5.0",
					},
				},
				{
					ID: "Microsoft.Extensions.Configuration.Abstractions@2.2.0",
					DependsOn: []string{
						"Microsoft.Extensions.Primitives@2.2.0",
					},
				},
				{
					ID:        "Microsoft.Extensions.DependencyInjection.Abstractions@2.2.0",
					DependsOn: nil,
				},
				{
					ID: "Microsoft.Extensions.FileProviders.Abstractions@2.2.0",
					DependsOn: []string{
						"Microsoft.Extensions.Primitives@2.2.0",
					},
				},
				{
					ID: "Microsoft.Extensions.Hosting.Abstractions@2.2.0",
					DependsOn: []string{
						"Microsoft.Extensions.Configuration.Abstractions@2.2.0",
						"Microsoft.Extensions.DependencyInjection.Abstractions@2.2.0",
						"Microsoft.Extensions.FileProviders.Abstractions@2.2.0",
						"Microsoft.Extensions.Logging.Abstractions@2.2.0",
					},
				},
				{
					ID:        "Microsoft.Extensions.Logging.Abstractions@2.2.0",
					DependsOn: nil,
				},
				{
					ID:        "Microsoft.Extensions.ObjectPool@2.2.0",
					DependsOn: nil,
				},
				{
					ID: "Microsoft.Extensions.Options@2.2.0",
					DependsOn: []string{
						"Microsoft.Extensions.DependencyInjection.Abstractions@2.2.0",
						"Microsoft.Extensions.Primitives@2.2.0",
						"System.ComponentModel.Annotations@4.5.0",
					},
				},
				{
					ID: "Microsoft.Extensions.Primitives@2.2.0",
					DependsOn: []string{
						"System.Memory@4.5.1",
						"System.Runtime.CompilerServices.Unsafe@4.5.1",
					},
				},
				{
					ID: "Microsoft.Net.Http.Headers@2.2.0",
					DependsOn: []string{
						"System.Buffers@4.5.0",
						"Microsoft.Extensions.Primitives@2.2.0",
					},
				},
				{
					ID:        "Microsoft.NETCore.Platforms@2.0.0",
					DependsOn: nil,
				},
				{
					ID:        "System.Buffers@4.5.0",
					DependsOn: nil,
				},
				{
					ID:        "System.ComponentModel.Annotations@4.5.0",
					DependsOn: nil,
				},
				{
					ID:        "System.IO.Pipelines@4.5.3",
					DependsOn: nil,
				},
				{
					ID:        "System.Memory@4.5.1",
					DependsOn: nil,
				},
				{
					ID:        "System.Runtime.CompilerServices.Unsafe@4.5.1",
					DependsOn: nil,
				},
				{
					ID:        "System.Text.Encodings.Web@4.5.0",
					DependsOn: nil,
				},
				{
					ID: "System.Security.Principal.Windows@4.5.0",
					DependsOn: []string{
						"Microsoft.NETCore.Platforms@2.0.0",
					},
				},
			},
		},
		{
			file: "testdata/ExampleApp1.deps.json",
			wantLibs: []types.Library{
				{ID: "Newtonsoft.Json@13.0.1", Name: "Newtonsoft.Json", Version: "13.0.1", Locations: []types.Location{{StartLine: 33, EndLine: 39}}},
				{ID: "ExampleApp1@1.0.0", Name: "ExampleApp1", Version: "1.0.0", Locations: []types.Location{{StartLine: 28, EndLine: 32}}},
			},
			wantDeps: []types.Dependency{
				{
					ID: "ExampleApp1@1.0.0",
					DependsOn: []string{
						"Newtonsoft.Json@13.0.1",
					},
				},
				{
					ID:        "Newtonsoft.Json@13.0.1",
					DependsOn: nil,
				},
			},
		},
		{
			file:     "testdata/NoLibraries.deps.json",
			wantLibs: nil,
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
