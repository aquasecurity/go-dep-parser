package nuget

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	NuGetNormal = []types.Library{
		{"Microsoft.NET.Test.Sdk", "16.6.1"},
		{"Microsoft.CodeCoverage", "16.6.1"},
		{"Microsoft.TestPlatform.TestHost", "16.6.1"},
		{"Newtonsoft.Json", "12.0.3"},
		{"System.Runtime", "4.3.1"},
	}

	NuGetWithTransitive = []types.Library{
		{"Microsoft.NET.Test.Sdk", "16.6.1"},
		{"Microsoft.CodeCoverage", "16.6.1"},
		{"Microsoft.TestPlatform.TestHost", "16.6.1"},
		{"Newtonsoft.Json", "12.0.3"},
		{"System.Runtime", "4.3.1"},
		{"NETStandard.Library", "1.6.1"},
		{"Microsoft.NETCore.Platforms", "1.1.0"},
		{"Microsoft.Win32.Primitives", "4.3.0"},
		{"System.AppContext", "4.3.0"},
		{"System.Collections", "4.3.0"},
		{"System.Collections.Concurrent", "4.3.0"},
		{"System.Console", "4.3.0"},
		{"System.Diagnostics.Debug", "4.3.0"},
		{"System.Diagnostics.Tools", "4.3.0"},
		{"NuGet.Frameworks", "5.0.0"},
	}

	NuGetMany = []types.Library{
		{"Microsoft.NET.Test.Sdk", "16.6.1"},
		{"Microsoft.CodeCoverage", "16.6.1"},
		{"Microsoft.TestPlatform.TestHost", "16.6.1"},
		{"Newtonsoft.Json", "12.0.3"},
		{"xunit.runner.utility", "2.4.1"},
		{"NETStandard.Library", "1.6.0"},
		{"System.Runtime.Loader", "4.0.0"},
		{"xunit.abstractions", "2.0.3"},
		{"System.Runtime", "4.3.1"},
		{"NETStandard.Library", "1.6.1"},
		{"xunit.runner.visualstudio", "2.4.2"},
		{"Microsoft.NETCore.Platforms", "1.1.0"},
		{"Microsoft.Win32.Primitives", "4.3.0"},
		{"System.AppContext", "4.3.0"},
		{"System.Collections", "4.3.0"},
		{"System.Collections.Concurrent", "4.3.0"},
		{"System.Console", "4.3.0"},
		{"System.Diagnostics.Debug", "4.3.0"},
		{"System.Diagnostics.Tools", "4.3.0"},
		{"NuGet.Frameworks", "5.0.0"},
		{"runtime.ubuntu.16.10-x64.runtime.native.System.Security.Cryptography.OpenSsl", "4.3.0"},
		{"System.Linq", "4.3.0"},
		{"System.Resources.ResourceManager", "4.3.0"},
		{"System.Runtime", "4.3.0"},
		{"System.Runtime.Extensions", "4.3.0"},
	}
)
