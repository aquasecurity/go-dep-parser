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
		types.NewLibrary("Newtonsoft.Json", "12.0.3", ""),
		types.NewLibrary("NuGet.Frameworks", "5.7.0", ""),
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
		types.NewLibrary("Microsoft.Extensions.ApiDescription.Server", "3.0.0", ""),
		types.NewLibrary("Microsoft.OpenApi", "1.1.4", ""),
		types.NewLibrary("Newtonsoft.Json", "12.0.3", ""),
		types.NewLibrary("NuGet.Frameworks", "5.7.0", ""),
		types.NewLibrary("Swashbuckle.AspNetCore", "5.5.1", ""),
		types.NewLibrary("Swashbuckle.AspNetCore.Swagger", "5.5.1", ""),
		types.NewLibrary("Swashbuckle.AspNetCore.SwaggerGen", "5.5.1", ""),
		types.NewLibrary("Swashbuckle.AspNetCore.SwaggerUI", "5.5.1", ""),
	}

	// mcr.microsoft.com/dotnet/sdk:latest
	// apt -y update && apt -y install jq
	// cd /usr/local/src
	// dotnet new console
	// dotnet add package Newtonsoft.Json
	// dotnet add package AWSSDK.Core
	// dotnet restore --use-lock-file
	// cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\", \"\"},"'
	nuGetLegacy = []types.Library{
		types.NewLibrary("AWSSDK.Core", "3.5.1.30", ""),
		types.NewLibrary("Newtonsoft.Json", "12.0.3", ""),
	}

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
		types.NewLibrary("AWSSDK.Core", "3.5.1.30", ""),
		types.NewLibrary("Microsoft.Bcl.AsyncInterfaces", "1.1.0", ""),
		types.NewLibrary("Microsoft.CSharp", "4.3.0", ""),
		types.NewLibrary("Microsoft.NETCore.Platforms", "1.1.0", ""),
		types.NewLibrary("Microsoft.NETCore.Targets", "1.1.0", ""),
		types.NewLibrary("Microsoft.NETFramework.ReferenceAssemblies", "1.0.0", ""),
		types.NewLibrary("Microsoft.NETFramework.ReferenceAssemblies.net20", "1.0.0", ""),
		types.NewLibrary("Microsoft.NETFramework.ReferenceAssemblies.net40", "1.0.0", ""),
		types.NewLibrary("NETStandard.Library", "1.6.1", ""),
		types.NewLibrary("NETStandard.Library", "2.0.3", ""),
		types.NewLibrary("Newtonsoft.Json", "12.0.3", ""),
		types.NewLibrary("System.Collections", "4.3.0", ""),
		types.NewLibrary("System.ComponentModel", "4.3.0", ""),
		types.NewLibrary("System.ComponentModel.Primitives", "4.3.0", ""),
		types.NewLibrary("System.ComponentModel.TypeConverter", "4.3.0", ""),
		types.NewLibrary("System.Diagnostics.Debug", "4.3.0", ""),
		types.NewLibrary("System.Diagnostics.Tools", "4.3.0", ""),
		types.NewLibrary("System.Dynamic.Runtime", "4.3.0", ""),
		types.NewLibrary("System.Globalization", "4.3.0", ""),
		types.NewLibrary("System.IO", "4.3.0", ""),
		types.NewLibrary("System.Linq", "4.3.0", ""),
		types.NewLibrary("System.Linq.Expressions", "4.3.0", ""),
		types.NewLibrary("System.Net.Primitives", "4.3.0", ""),
		types.NewLibrary("System.ObjectModel", "4.3.0", ""),
		types.NewLibrary("System.Reflection", "4.3.0", ""),
		types.NewLibrary("System.Reflection.Extensions", "4.3.0", ""),
		types.NewLibrary("System.Reflection.Primitives", "4.3.0", ""),
		types.NewLibrary("System.Resources.ResourceManager", "4.3.0", ""),
		types.NewLibrary("System.Runtime", "4.3.0", ""),
		types.NewLibrary("System.Runtime.CompilerServices.Unsafe", "4.5.2", ""),
		types.NewLibrary("System.Runtime.Extensions", "4.3.0", ""),
		types.NewLibrary("System.Runtime.Serialization.Primitives", "4.3.0", ""),
		types.NewLibrary("System.Text.Encoding", "4.3.0", ""),
		types.NewLibrary("System.Text.Encoding.Extensions", "4.3.0", ""),
		types.NewLibrary("System.Text.RegularExpressions", "4.3.0", ""),
		types.NewLibrary("System.Threading", "4.3.0", ""),
		types.NewLibrary("System.Threading.Tasks", "4.3.0", ""),
		types.NewLibrary("System.Threading.Tasks.Extensions", "4.5.2", ""),
		types.NewLibrary("System.Xml.ReaderWriter", "4.3.0", ""),
		types.NewLibrary("System.Xml.XDocument", "4.3.0", ""),
	}
)
