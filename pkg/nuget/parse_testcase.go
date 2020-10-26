package nuget

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
    // mcr.microsoft.com/dotnet/sdk:latest
    // cd /usr/local/src
    // dotnet new mvc
    // dotnet add package Newtonsoft.Json
    // dotnet add package NuGet.Frameworks
    // dotnet restore --use-lock-file
    // cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\"},"'
    NuGetSimple = []types.Library{
        {"Newtonsoft.Json", "12.0.3"},
        {"NuGet.Frameworks", "5.7.0"},
    }

    // mcr.microsoft.com/dotnet/sdk:latest
    // cd /usr/local/src
    // dotnet new webapi
    // dotnet add package Newtonsoft.Json
    // dotnet add package NuGet.Frameworks
    // dotnet restore --use-lock-file
    // cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\"},"'
    NuGetSubDependencies = []types.Library{
        {"Microsoft.Extensions.ApiDescription.Server", "3.0.0"},
        {"Microsoft.OpenApi", "1.1.4"},
        {"Newtonsoft.Json", "12.0.3"},
        {"NuGet.Frameworks", "5.7.0"},
        {"Swashbuckle.AspNetCore", "5.5.1"},
        {"Swashbuckle.AspNetCore.Swagger", "5.5.1"},
        {"Swashbuckle.AspNetCore.SwaggerGen", "5.5.1"},
        {"Swashbuckle.AspNetCore.SwaggerUI", "5.5.1"},
    }

    // mcr.microsoft.com/dotnet/sdk:latest
    // cd /usr/local/src
    // dotnet new xunit
    // dotnet add package Newtonsoft.Json
    // dotnet add package NuGet.Frameworks
    // dotnet restore --use-lock-file
    // cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\"},"'
    NuGetComplex = []types.Library{
        {"Microsoft.CodeCoverage", "16.7.1"},
        {"Microsoft.NET.Test.Sdk", "16.7.1"},
        {"Microsoft.NETCore.Platforms", "1.1.0"},
        {"Microsoft.NETCore.Targets", "1.1.0"},
        {"Microsoft.TestPlatform.ObjectModel", "16.7.1"},
        {"Microsoft.TestPlatform.TestHost", "16.7.1"},
        {"Microsoft.Win32.Primitives", "4.3.0"},
        {"NETStandard.Library", "1.6.1"},
        {"Newtonsoft.Json", "12.0.3"},
        {"NuGet.Frameworks", "5.7.0"},
        {"System.AppContext", "4.3.0"},
        {"System.Buffers", "4.3.0"},
        {"System.Collections", "4.3.0"},
        {"System.Collections.Concurrent", "4.3.0"},
        {"System.Console", "4.3.0"},
        {"System.Diagnostics.Debug", "4.3.0"},
        {"System.Diagnostics.DiagnosticSource", "4.3.0"},
        {"System.Diagnostics.Tools", "4.3.0"},
        {"System.Diagnostics.Tracing", "4.3.0"},
        {"System.Globalization", "4.3.0"},
        {"System.Globalization.Calendars", "4.3.0"},
        {"System.Globalization.Extensions", "4.3.0"},
        {"System.IO", "4.3.0"},
        {"System.IO.Compression", "4.3.0"},
        {"System.IO.Compression.ZipFile", "4.3.0"},
        {"System.IO.FileSystem", "4.3.0"},
        {"System.IO.FileSystem.Primitives", "4.3.0"},
        {"System.Linq", "4.3.0"},
        {"System.Linq.Expressions", "4.3.0"},
        {"System.Net.Http", "4.3.0"},
        {"System.Net.Primitives", "4.3.0"},
        {"System.Net.Sockets", "4.3.0"},
        {"System.ObjectModel", "4.3.0"},
        {"System.Reflection", "4.3.0"},
        {"System.Reflection.Emit", "4.3.0"},
        {"System.Reflection.Emit.ILGeneration", "4.3.0"},
        {"System.Reflection.Emit.Lightweight", "4.3.0"},
        {"System.Reflection.Extensions", "4.3.0"},
        {"System.Reflection.Primitives", "4.3.0"},
        {"System.Reflection.TypeExtensions", "4.3.0"},
        {"System.Resources.ResourceManager", "4.3.0"},
        {"System.Runtime", "4.3.0"},
        {"System.Runtime.Extensions", "4.3.0"},
        {"System.Runtime.Handles", "4.3.0"},
        {"System.Runtime.InteropServices", "4.3.0"},
        {"System.Runtime.InteropServices.RuntimeInformation", "4.3.0"},
        {"System.Runtime.Numerics", "4.3.0"},
        {"System.Security.Cryptography.Algorithms", "4.3.0"},
        {"System.Security.Cryptography.Cng", "4.3.0"},
        {"System.Security.Cryptography.Csp", "4.3.0"},
        {"System.Security.Cryptography.Encoding", "4.3.0"},
        {"System.Security.Cryptography.OpenSsl", "4.3.0"},
        {"System.Security.Cryptography.Primitives", "4.3.0"},
        {"System.Security.Cryptography.X509Certificates", "4.3.0"},
        {"System.Text.Encoding", "4.3.0"},
        {"System.Text.Encoding.Extensions", "4.3.0"},
        {"System.Text.RegularExpressions", "4.3.0"},
        {"System.Threading", "4.3.0"},
        {"System.Threading.Tasks", "4.3.0"},
        {"System.Threading.Tasks.Extensions", "4.3.0"},
        {"System.Threading.Timer", "4.3.0"},
        {"System.Xml.ReaderWriter", "4.3.0"},
        {"System.Xml.XDocument", "4.3.0"},
        {"coverlet.collector", "1.3.0"},
        {"runtime.debian.8-x64.runtime.native.System.Security.Cryptography.OpenSsl", "4.3.0"},
        {"runtime.fedora.23-x64.runtime.native.System.Security.Cryptography.OpenSsl", "4.3.0"},
        {"runtime.fedora.24-x64.runtime.native.System.Security.Cryptography.OpenSsl", "4.3.0"},
        {"runtime.native.System", "4.3.0"},
        {"runtime.native.System.IO.Compression", "4.3.0"},
        {"runtime.native.System.Net.Http", "4.3.0"},
        {"runtime.native.System.Security.Cryptography.Apple", "4.3.0"},
        {"runtime.native.System.Security.Cryptography.OpenSsl", "4.3.0"},
        {"runtime.opensuse.13.2-x64.runtime.native.System.Security.Cryptography.OpenSsl", "4.3.0"},
        {"runtime.opensuse.42.1-x64.runtime.native.System.Security.Cryptography.OpenSsl", "4.3.0"},
        {"runtime.osx.10.10-x64.runtime.native.System.Security.Cryptography.Apple", "4.3.0"},
        {"runtime.osx.10.10-x64.runtime.native.System.Security.Cryptography.OpenSsl", "4.3.0"},
        {"runtime.rhel.7-x64.runtime.native.System.Security.Cryptography.OpenSsl", "4.3.0"},
        {"runtime.ubuntu.14.04-x64.runtime.native.System.Security.Cryptography.OpenSsl", "4.3.0"},
        {"runtime.ubuntu.16.04-x64.runtime.native.System.Security.Cryptography.OpenSsl", "4.3.0"},
        {"runtime.ubuntu.16.10-x64.runtime.native.System.Security.Cryptography.OpenSsl", "4.3.0"},
        {"xunit", "2.4.1"},
        {"xunit.abstractions", "2.0.3"},
        {"xunit.analyzers", "0.10.0"},
        {"xunit.assert", "2.4.1"},
        {"xunit.core", "2.4.1"},
        {"xunit.extensibility.core", "2.4.1"},
        {"xunit.extensibility.execution", "2.4.1"},
        {"xunit.runner.visualstudio", "2.4.3"},
    }

    // mcr.microsoft.com/dotnet/sdk:latest
    // cd /usr/local/src
    // dotnet new console
    // dotnet add package Newtonsoft.Json
    // dotnet add package AWSSDK.Core
    // dotnet restore --use-lock-file
    // cat packages.lock.json | jq -rc '.dependencies[] | keys[] as $k | "{\"\($k)\", \"\(.[$k] | .resolved)\"},"'
    NuGetLegacy = []types.Library{
        {"AWSSDK.Core", "3.5.1.30"},
        {"Newtonsoft.Json", "12.0.3"},
    }
)
