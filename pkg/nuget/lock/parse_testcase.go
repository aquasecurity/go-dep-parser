package lock

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --rm -i -t mcr.microsoft.com/dotnet/sdk:latest
	// apt -y update && apt -y install jq
	// cd /usr/local/src
	// dotnet new mvc
	// dotnet add package Newtonsoft.Json
	// dotnet add package NuGet.Frameworks
	// dotnet restore --use-lock-file
	// cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\", \"\"},"'
	nuGetSimple = []types.Library{
		{Name: "Newtonsoft.Json", Version: "12.0.3"},
		{Name: "NuGet.Frameworks", Version: "5.7.0"},
	}
	nuGetSimpleDeps = []types.Dependency{
		{ID: "Newtonsoft.Json@12.0.3", DependsOn: nil},
		{ID: "NuGet.Frameworks@5.7.0", DependsOn: nil},
	}

	// docker run --rm -i -t mcr.microsoft.com/dotnet/sdk:latest
	// apt -y update && apt -y install jq
	// cd /usr/local/src
	// dotnet new webapi
	// dotnet add package Newtonsoft.Json
	// dotnet add package NuGet.Frameworks
	// dotnet restore --use-lock-file
	// cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\", \"\"},"'
	nuGetSubDependencies = []types.Library{
		{Name: "Microsoft.Extensions.ApiDescription.Server", Version: "3.0.0"},
		{Name: "Microsoft.OpenApi", Version: "1.1.4"},
		{Name: "Newtonsoft.Json", Version: "12.0.3"},
		{Name: "NuGet.Frameworks", Version: "5.7.0"},
		{Name: "Swashbuckle.AspNetCore", Version: "5.5.1"},
		{Name: "Swashbuckle.AspNetCore.Swagger", Version: "5.5.1"},
		{Name: "Swashbuckle.AspNetCore.SwaggerGen", Version: "5.5.1"},
		{Name: "Swashbuckle.AspNetCore.SwaggerUI", Version: "5.5.1"},
	}
	nuGetSubDependenciesDeps = []types.Dependency{
		{ID: "Microsoft.Extensions.ApiDescription.Server@3.0.0", DependsOn: nil},
		{ID: "Microsoft.OpenApi@1.1.4", DependsOn: nil},
		{ID: "Swashbuckle.AspNetCore.Swagger@5.5.1", DependsOn: []string{"Microsoft.OpenApi@1.1.4"}},
		{ID: "Swashbuckle.AspNetCore.SwaggerGen@5.5.1", DependsOn: []string{"Swashbuckle.AspNetCore.Swagger@5.5.1"}},
		{ID: "Swashbuckle.AspNetCore.SwaggerUI@5.5.1", DependsOn: nil},
		{ID: "Newtonsoft.Json@12.0.3", DependsOn: nil},
		{ID: "NuGet.Frameworks@5.7.0", DependsOn: nil},
		{ID: "Swashbuckle.AspNetCore@5.5.1", DependsOn: []string{"Microsoft.Extensions.ApiDescription.Server@3.0.0", "Swashbuckle.AspNetCore.Swagger@5.5.1", "Swashbuckle.AspNetCore.SwaggerGen@5.5.1", "Swashbuckle.AspNetCore.SwaggerUI@5.5.1"}}}

	// mcr.microsoft.com/dotnet/sdk:latest
	// apt -y update && apt -y install jq
	// cd /usr/local/src
	// dotnet new console
	// dotnet add package Newtonsoft.Json
	// dotnet add package AWSSDK.Core
	// dotnet restore --use-lock-file
	// cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\", \"\"},"'
	nuGetLegacy = []types.Library{
		{Name: "AWSSDK.Core", Version: "3.5.1.30"},
		{Name: "Newtonsoft.Json", Version: "12.0.3"},
	}
	nuGetLegacyDeps = []types.Dependency{{ID: "Newtonsoft.Json@12.0.3", DependsOn: nil}, {ID: "AWSSDK.Core@3.5.1.30", DependsOn: nil}}

	// docker run --rm -i -t mcr.microsoft.com/dotnet/sdk:latest
	// apt -y update && apt -y install jq
	// cd /usr/local/src
	// dotnet new classlib -f net5.0
	// sed -i 's~TargetFramework>net5.0</TargetFramework~TargetFrameworks>net4.0;netstandard2.0;netstandard1.0;net35;net2.0</TargetFrameworks~' src.csproj
	// dotnet add package Newtonsoft.Json
	// dotnet restore --use-lock-file
	// dotnet add package AWSSDK.Core
	// cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\", \"\"},"' | sort -u
	nuGetMultiTarget = []types.Library{
		{Name: "AWSSDK.Core", Version: "3.5.1.30"},
		{Name: "Microsoft.Bcl.AsyncInterfaces", Version: "1.1.0"},
		{Name: "Microsoft.CSharp", Version: "4.3.0"},
		{Name: "Microsoft.NETCore.Platforms", Version: "1.1.0"},
		{Name: "Microsoft.NETCore.Targets", Version: "1.1.0"},
		{Name: "Microsoft.NETFramework.ReferenceAssemblies", Version: "1.0.0"},
		{Name: "Microsoft.NETFramework.ReferenceAssemblies.net20", Version: "1.0.0"},
		{Name: "Microsoft.NETFramework.ReferenceAssemblies.net40", Version: "1.0.0"},
		{Name: "NETStandard.Library", Version: "1.6.1"},
		{Name: "NETStandard.Library", Version: "2.0.3"},
		{Name: "Newtonsoft.Json", Version: "12.0.3"},
		{Name: "System.Collections", Version: "4.3.0"},
		{Name: "System.ComponentModel", Version: "4.3.0"},
		{Name: "System.ComponentModel.Primitives", Version: "4.3.0"},
		{Name: "System.ComponentModel.TypeConverter", Version: "4.3.0"},
		{Name: "System.Diagnostics.Debug", Version: "4.3.0"},
		{Name: "System.Diagnostics.Tools", Version: "4.3.0"},
		{Name: "System.Dynamic.Runtime", Version: "4.3.0"},
		{Name: "System.Globalization", Version: "4.3.0"},
		{Name: "System.IO", Version: "4.3.0"},
		{Name: "System.Linq", Version: "4.3.0"},
		{Name: "System.Linq.Expressions", Version: "4.3.0"},
		{Name: "System.Net.Primitives", Version: "4.3.0"},
		{Name: "System.ObjectModel", Version: "4.3.0"},
		{Name: "System.Reflection", Version: "4.3.0"},
		{Name: "System.Reflection.Extensions", Version: "4.3.0"},
		{Name: "System.Reflection.Primitives", Version: "4.3.0"},
		{Name: "System.Resources.ResourceManager", Version: "4.3.0"},
		{Name: "System.Runtime", Version: "4.3.0"},
		{Name: "System.Runtime.CompilerServices.Unsafe", Version: "4.5.2"},
		{Name: "System.Runtime.Extensions", Version: "4.3.0"},
		{Name: "System.Runtime.Serialization.Primitives", Version: "4.3.0"},
		{Name: "System.Text.Encoding", Version: "4.3.0"},
		{Name: "System.Text.Encoding.Extensions", Version: "4.3.0"},
		{Name: "System.Text.RegularExpressions", Version: "4.3.0"},
		{Name: "System.Threading", Version: "4.3.0"},
		{Name: "System.Threading.Tasks", Version: "4.3.0"},
		{Name: "System.Threading.Tasks.Extensions", Version: "4.5.2"},
		{Name: "System.Xml.ReaderWriter", Version: "4.3.0"},
		{Name: "System.Xml.XDocument", Version: "4.3.0"},
	}
	nuGetMultiTargetDeps = []types.Dependency{
		{ID: "AWSSDK.Core@3.5.1.30", DependsOn: []string{"Microsoft.Bcl.AsyncInterfaces@1.1.0"}},
		{ID: "Microsoft.Bcl.AsyncInterfaces@1.1.0", DependsOn: []string{"System.Threading.Tasks.Extensions@4.5.2"}},
		{ID: "Microsoft.CSharp@4.3.0", DependsOn: []string{"System.Dynamic.Runtime@4.3.0", "System.Linq.Expressions@4.3.0", "System.Runtime@4.3.0"}},
		{ID: "Microsoft.NETCore.Platforms@1.1.0", DependsOn: nil},
		{ID: "Microsoft.NETCore.Targets@1.1.0", DependsOn: nil},
		{ID: "Microsoft.NETFramework.ReferenceAssemblies.net20@1.0.0", DependsOn: nil},
		{ID: "Microsoft.NETFramework.ReferenceAssemblies.net40@1.0.0", DependsOn: nil},
		{ID: "Microsoft.NETFramework.ReferenceAssemblies@1.0.0", DependsOn: []string{"Microsoft.NETFramework.ReferenceAssemblies.net20@1.0.0", "Microsoft.NETFramework.ReferenceAssemblies.net40@1.0.0"}},
		{ID: "NETStandard.Library@1.6.1", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "System.Collections@4.3.0", "System.Diagnostics.Debug@4.3.0", "System.Diagnostics.Tools@4.3.0", "System.Globalization@4.3.0", "System.IO@4.3.0", "System.Linq.Expressions@4.3.0", "System.Linq@4.3.0", "System.Net.Primitives@4.3.0", "System.ObjectModel@4.3.0", "System.Reflection.Extensions@4.3.0", "System.Reflection.Primitives@4.3.0", "System.Reflection@4.3.0", "System.Resources.ResourceManager@4.3.0", "System.Runtime.Extensions@4.3.0", "System.Runtime@4.3.0", "System.Text.Encoding.Extensions@4.3.0", "System.Text.Encoding@4.3.0", "System.Text.RegularExpressions@4.3.0", "System.Threading.Tasks@4.3.0", "System.Threading@4.3.0", "System.Xml.ReaderWriter@4.3.0", "System.Xml.XDocument@4.3.0"}},
		{ID: "NETStandard.Library@2.0.3", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0"}},
		{ID: "Newtonsoft.Json@12.0.3", DependsOn: []string{"Microsoft.CSharp@4.3.0", "NETStandard.Library@1.6.1", "System.ComponentModel.TypeConverter@4.3.0", "System.Runtime.Serialization.Primitives@4.3.0"}},
		{ID: "System.Collections@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Runtime@4.3.0"}},
		{ID: "System.ComponentModel.Primitives@4.3.0", DependsOn: []string{"System.ComponentModel@4.3.0", "System.Resources.ResourceManager@4.3.0", "System.Runtime@4.3.0"}},
		{ID: "System.ComponentModel.TypeConverter@4.3.0", DependsOn: []string{"System.Collections@4.3.0", "System.ComponentModel.Primitives@4.3.0", "System.ComponentModel@4.3.0", "System.Globalization@4.3.0", "System.Reflection.Extensions@4.3.0", "System.Reflection.Primitives@4.3.0", "System.Reflection@4.3.0", "System.Resources.ResourceManager@4.3.0", "System.Runtime.Extensions@4.3.0", "System.Runtime@4.3.0", "System.Threading@4.3.0"}},
		{ID: "System.ComponentModel@4.3.0", DependsOn: []string{"System.Runtime@4.3.0"}},
		{ID: "System.Diagnostics.Debug@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Runtime@4.3.0"}},
		{ID: "System.Diagnostics.Tools@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Runtime@4.3.0"}},
		{ID: "System.Dynamic.Runtime@4.3.0", DependsOn: []string{"System.Linq.Expressions@4.3.0", "System.ObjectModel@4.3.0", "System.Reflection@4.3.0", "System.Runtime@4.3.0"}},
		{ID: "System.Globalization@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Runtime@4.3.0"}},
		{ID: "System.IO@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Runtime@4.3.0", "System.Text.Encoding@4.3.0", "System.Threading.Tasks@4.3.0"}},
		{ID: "System.Linq.Expressions@4.3.0", DependsOn: []string{"System.Reflection@4.3.0", "System.Runtime@4.3.0"}},
		{ID: "System.Linq@4.3.0", DependsOn: []string{"System.Collections@4.3.0", "System.Runtime@4.3.0"}},
		{ID: "System.Net.Primitives@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Runtime@4.3.0"}},
		{ID: "System.ObjectModel@4.3.0", DependsOn: []string{"System.Runtime@4.3.0"}},
		{ID: "System.Reflection.Extensions@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Reflection@4.3.0", "System.Runtime@4.3.0"}},
		{ID: "System.Reflection.Primitives@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Runtime@4.3.0"}},
		{ID: "System.Reflection@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.IO@4.3.0", "System.Reflection.Primitives@4.3.0", "System.Runtime@4.3.0"}},
		{ID: "System.Resources.ResourceManager@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Globalization@4.3.0", "System.Reflection@4.3.0", "System.Runtime@4.3.0"}},
		{ID: "System.Runtime.CompilerServices.Unsafe@4.5.2", DependsOn: nil},
		{ID: "System.Runtime.Extensions@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Runtime@4.3.0"}},
		{ID: "System.Runtime.Serialization.Primitives@4.3.0", DependsOn: []string{"System.Runtime@4.3.0"}},
		{ID: "System.Runtime@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0"}},
		{ID: "System.Text.Encoding.Extensions@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Runtime@4.3.0", "System.Text.Encoding@4.3.0"}},
		{ID: "System.Text.Encoding@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Runtime@4.3.0"}},
		{ID: "System.Text.RegularExpressions@4.3.0", DependsOn: []string{"System.Runtime@4.3.0"}},
		{ID: "System.Threading.Tasks.Extensions@4.5.2", DependsOn: []string{"System.Runtime.CompilerServices.Unsafe@4.5.2"}},
		{ID: "System.Threading.Tasks@4.3.0", DependsOn: []string{"Microsoft.NETCore.Platforms@1.1.0", "Microsoft.NETCore.Targets@1.1.0", "System.Runtime@4.3.0"}},
		{ID: "System.Threading@4.3.0", DependsOn: []string{"System.Runtime@4.3.0", "System.Threading.Tasks@4.3.0"}},
		{ID: "System.Xml.ReaderWriter@4.3.0", DependsOn: []string{"System.IO@4.3.0", "System.Runtime@4.3.0", "System.Text.Encoding@4.3.0", "System.Threading.Tasks@4.3.0"}},
		{ID: "System.Xml.XDocument@4.3.0", DependsOn: []string{"System.IO@4.3.0", "System.Runtime@4.3.0", "System.Xml.ReaderWriter@4.3.0"}},
	}
)
