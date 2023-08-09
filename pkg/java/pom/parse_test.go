package pom_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/java/pom"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestPom_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		local     bool
		offline   bool
		want      []types.Library
		wantDeps  []types.Dependency
		wantErr   string
	}{
		{
			name:      "local repository",
			inputFile: filepath.Join("testdata", "happy", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:happy",
					Version: "1.0.0",
					License: "BSD-3-Clause",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.happy:1.0.0",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
			},
		},
		{
			name:      "nested dependancies",
			inputFile: filepath.Join("testdata", "nested2", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "org.example.example-nested2:app",
					Version: "1.0.0",
				},
				{
					Name:    "org.example.example-nested2:package-a",
					Version: "1.0.0",
				},
				{
					Name:    "org.example.example-nested2:package-aa",
					Version: "1.0.0",
				},
				{
					Name:    "org.example.example-nested2:package-aaa",
					Version: "1.0.0",
				},
				{
					Name:    "org.example.example-nested2:package-ab",
					Version: "1.0.0",
				},
				{
					Name:    "org.example.example-nested2:package-ac",
					Version: "1.0.0",
				},
				{
					Name:    "org.example.example-nested2:package-b",
					Version: "1.0.0",
				},
				{
					Name:    "org.example.example-nested2:package-ba",
					Version: "1.0.0",
				},
				{
					Name:    "org.example.example-nested2:package-baa",
					Version: "1.0.0",
				},
				{
					Name:    "org.example.example-nested2:package-bb",
					Version: "1.0.0",
				},
				{
					Name:    "org.example.example-nested2:package-bc",
					Version: "1.0.0",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "org.example.example-nested2.app:1.0.0",
					DependsOn: []string{"org.example.example-nested2.package-a:1.0.0", "org.example.example-nested2.package-b:1.0.0"},
				},
				{
					ID:        "org.example.example-nested2.package-a:1.0.0",
					DependsOn: []string{"org.example.example-nested2.package-aa:1.0.0", "org.example.example-nested2.package-ab:1.0.0", "org.example.example-nested2.package-ac:1.0.0"},
				},
				{
					ID:        "org.example.example-nested2.package-b:1.0.0",
					DependsOn: []string{"org.example.example-nested2.package-ba:1.0.0", "org.example.example-nested2.package-bb:1.0.0", "org.example.example-nested2.package-bc:1.0.0"},
				},
				{
					ID:        "org.example.example-nested2.package-aa:1.0.0",
					DependsOn: []string{"org.example.example-nested2.package-aaa:1.0.0"},
				},
				{
					ID:        "org.example.example-nested2.package-ba:1.0.0",
					DependsOn: []string{"org.example.example-nested2.package-baa:1.0.0"},
				},
			},
		},
		{
			name:      "remote repository",
			inputFile: filepath.Join("testdata", "happy", "pom.xml"),
			local:     false,
			want: []types.Library{
				{
					Name:    "com.example:happy",
					Version: "1.0.0",
					License: "BSD-3-Clause",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.happy:1.0.0",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
			},
		},
		{
			name:      "offline mode",
			inputFile: filepath.Join("testdata", "offline", "pom.xml"),
			local:     false,
			offline:   true,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "0.0.1",
				},
				{
					Name:    "org.example:example-offline",
					Version: "2.3.4",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.child:0.0.1",
					DependsOn: []string{"org.example.example-offline:2.3.4"},
				},
			},
		},
		{
			name:      "inherit parent properties",
			inputFile: filepath.Join("testdata", "parent-properties", "child", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.child:1.0.0",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
			},
		},

		{
			name:      "inherit project properties from parent",
			inputFile: filepath.Join("testdata", "project-version-from-parent", "child", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "2.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
			},
		},
		{
			name:      "inherit properties in parent depManagement with import scope",
			inputFile: filepath.Join("testdata", "inherit-props", "base", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:test",
					Version: "0.0.1-SNAPSHOT",
				},
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
			},
		},
		{
			name:      "dependencyManagement prefers child properties",
			inputFile: filepath.Join("testdata", "parent-child-properties", "child", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "4.0.0",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
				},
			},
		},
		{
			name:      "inherit parent dependencies",
			inputFile: filepath.Join("testdata", "parent-dependencies", "child", "pom.xml"),
			local:     false,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "1.0.0-SNAPSHOT",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.child:1.0.0-SNAPSHOT",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
			},
		},
		{
			name:      "inherit parent dependencyManagement",
			inputFile: filepath.Join("testdata", "parent-dependency-management", "child", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "3.0.0",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.child:3.0.0",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
			},
		},
		{
			name:      "transitive parents",
			inputFile: filepath.Join("testdata", "transitive-parents", "base", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:base",
					Version: "4.0.0",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:example-child",
					Version: "2.0.0",
				},
			},
		},
		{
			name:      "parent relativePath",
			inputFile: filepath.Join("testdata", "parent-relative-path", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.child:1.0.0",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
			},
		},
		{
			name:      "parent version in property",
			inputFile: filepath.Join("testdata", "parent-version-is-property", "child", "pom.xml"),
			local:     false,
			want: []types.Library{
				{
					Name:    "com.example:child",
					Version: "1.0.0-SNAPSHOT",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.1.1",
				},
			},
		},
		{
			name:      "parent in a remote repository",
			inputFile: filepath.Join("testdata", "parent-remote-repository", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "org.example:child",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "org.example.child:1.0.0",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
			},
		},
		{
			name:      "soft requirement",
			inputFile: filepath.Join("testdata", "soft-requirement", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:soft",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.soft:1.0.0",
					DependsOn: []string{"org.example.example-api:1.7.30", "org.example.example-dependency:1.2.3"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
				{
					ID:        "org.example.example-dependency:1.2.3",
					DependsOn: []string{"org.example.example-api:2.0.0"},
				},
			},
		},
		{
			name:      "soft requirement with transitive dependencies",
			inputFile: filepath.Join("testdata", "soft-requirement-with-transitive-dependencies", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:soft-transitive",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
				},
				{
					Name:    "org.example:example-dependency2",
					Version: "2.3.4",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.soft-transitive:1.0.0",
					DependsOn: []string{"org.example.example-dependency:1.2.3", "org.example.example-dependency2:2.3.4"},
				},
				{
					ID:        "org.example.example-dependency:1.2.3",
					DependsOn: []string{"org.example.example-api:2.0.0"},
				},
				{
					ID:        "org.example.example-dependency2:2.3.4",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
			},
		},
		{
			name:      "hard requirement for the specified version",
			inputFile: filepath.Join("testdata", "hard-requirement", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:hard",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.4",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.hard:1.0.0",
					DependsOn: []string{"org.example.example-api:1.7.30", "org.example.example-dependency:1.2.4"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
				{
					ID:        "org.example.example-dependency:1.2.3",
					DependsOn: []string{"org.example.example-api:2.0.0"},
				},
			},
		},
		{
			name:      "version requirement",
			inputFile: filepath.Join("testdata", "version-requirement", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:hard",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.hard:1.0.0",
					DependsOn: []string{"org.example.example-api:"}, //???? TODO
				},
			},
		},
		{
			name:      "import dependencyManagement",
			inputFile: filepath.Join("testdata", "import-dependency-management", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:import",
					Version: "2.0.0",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.import:2.0.0",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
			},
		},
		{
			name:      "import multiple dependencyManagement",
			inputFile: filepath.Join("testdata", "import-dependency-management-multiple", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:import",
					Version: "2.0.0",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.import:2.0.0",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
			},
		},
		{
			name:      "exclusions",
			inputFile: filepath.Join("testdata", "exclusions", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:exclusions",
					Version: "3.0.0",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
				},
				{
					Name:    "org.example:example-nested",
					Version: "3.3.3",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.exclusions:3.0.0",
					DependsOn: []string{"org.example.example-nested:3.3.3"},
				},
				{
					ID:        "org.example.example-nested:3.3.3",
					DependsOn: []string{"org.example.example-dependency:1.2.3"},
				},
			},
		},
		{
			name:      "exclusions with wildcards",
			inputFile: filepath.Join("testdata", "wildcard-exclusions", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:wildcard-exclusions",
					Version: "4.0.0",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
				},
				{
					Name:    "org.example:example-dependency2",
					Version: "2.3.4",
				},
				{
					Name:    "org.example:example-nested",
					Version: "3.3.3",
				},
			},
		},
		{
			name:      "multi module",
			inputFile: filepath.Join("testdata", "multi-module", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:aggregation",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					Name:    "com.example:module",
					Version: "1.1.1",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.module:1.1.1",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
			},
		},
		{
			name:      "multi module soft requirement",
			inputFile: filepath.Join("testdata", "multi-module-soft-requirement", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:aggregation",
					Version: "1.0.0",
				},
				{
					Name:    "com.example:module1",
					Version: "1.1.1",
				},
				{
					Name:    "com.example:module2",
					Version: "1.1.1",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.module1:1.1.1",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
				{
					ID:        "com.example.module2:1.1.1",
					DependsOn: []string{"org.example.example-api:2.0.0"},
				},
			},
		},
		{
			name:      "overwrite artifact version from dependencyManagement in the root POM",
			inputFile: filepath.Join("testdata", "root-pom-dep-management", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:root-pom-dep-management",
					Version: "1.0.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
				// dependency version is taken from `com.example:root-pom-dep-management` from dependencyManagement
				// not from `com.example:example-nested` from `com.example:example-nested`
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.4",
				},
				{
					Name:    "org.example:example-nested",
					Version: "3.3.3",
				},
			},
		},
		{
			name:      "transitive dependencyManagement should not be inherited",
			inputFile: "testdata/transitive-dependency-management/pom.xml",
			local:     true,
			want: []types.Library{
				// Managed dependencies (org.example:example-api:1.7.30) in org.example:example-dependency-management3
				// should not affect dependencies of example-dependency (org.example:example-api:2.0.0)
				{
					Name:    "org.example:example-api",
					Version: "2.0.0",
				},
				{
					Name:    "org.example:example-dependency",
					Version: "1.2.3",
				},
				{
					Name:    "org.example:example-dependency-management3",
					Version: "1.1.1",
				},
				{
					Name:    "org.example:transitive-dependency-management",
					Version: "2.0.0",
				},
			},
		},
		{
			name:      "parent not found",
			inputFile: filepath.Join("testdata", "not-found-parent", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:no-parent",
					Version: "1.0-SNAPSHOT",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-api",
					Version: "1.7.30",
				},
				{
					Name:    "org.example:utils",
					Version: "1.7.30",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.no-parent:1.0-SNAPSHOT",
					DependsOn: []string{"org.example.example-api:1.7.30"},
				},
				{
					ID:        "org.example.example-api:1.7.30",
					DependsOn: []string{"org.example.utils:1.7.30"},
				},
			},
		},
		{
			name:      "dependency not found",
			inputFile: filepath.Join("testdata", "not-found-dependency", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:not-found-dependency",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
				{
					Name:    "org.example:example-not-found",
					Version: "999",
				},
			},
			wantDeps: []types.Dependency{
				{
					ID:        "com.example.not-found-dependency:1.0.0",
					DependsOn: []string{"org.example.example-not-found:999"},
				},
			},
		},
		{
			name:      "module not found - unable to parse module",
			inputFile: filepath.Join("testdata", "not-found-module", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:aggregation",
					Version: "1.0.0",
					License: "Apache 2.0",
				},
			},
		},
		{
			name:      "multiply licenses",
			inputFile: filepath.Join("testdata", "multiply-licenses", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example:multiply-licenses",
					Version: "1.0.0",
					License: "MIT, Apache 2.0",
				},
			},
		},
		{
			name:      "inherit parent license",
			inputFile: filepath.Join("testdata", "inherit-license", "module", "submodule", "pom.xml"),
			local:     true,
			want: []types.Library{
				{
					Name:    "com.example.app:submodule",
					Version: "1.0.0",
					License: "Apache-2.0",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			var remoteRepos []string
			if tt.local {
				// for local repository
				t.Setenv("MAVEN_HOME", "testdata")
			} else {
				// for remote repository
				h := http.FileServer(http.Dir(filepath.Join("testdata", "repository")))
				ts := httptest.NewServer(h)
				remoteRepos = []string{ts.URL}
			}

			p := pom.NewParser(tt.inputFile, pom.WithRemoteRepos(remoteRepos), pom.WithOffline(tt.offline))

			libs, deps, err := p.Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			sort.Slice(libs, func(i, j int) bool {
				return libs[i].Name < libs[j].Name
			})

			assert.Equal(t, tt.want, libs)

			if tt.wantDeps != nil {
				assert.Equal(t, tt.wantDeps, deps)
			}
		})
	}
}
