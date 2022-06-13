package pnpm

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name node --rm -it node:16-alpine sh
	// npm install -g pnpm
	// pnpm add promise jquery
	// pnpm list --prod -depth 10 | grep -E -o "\S+\s+[0-9]+(\.[0-9]+)+$" | awk '{printf("{\""$1"\", \""$2"\",\"\"},\n")}' | sort -u
	pnpmNormal = []types.Library{
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Indirect: true},
		{ID: "jquery@3.6.0", Name: "jquery", Version: "3.6.0", Indirect: false},
		{ID: "promise@8.1.0", Name: "promise", Version: "8.1.0", Indirect: false},
	}
	pnpmNormalDeps = []types.Dependency{
		{
			ID:        "promise@8.1.0",
			DependsOn: []string{"asap@2.0.6"},
		},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm install -g pnpm
	// pnpm add react redux
	// pnpm add -D mocha
	// pnpm list --prod --depth 10 | grep -E -o "\S+\s+[0-9]+(\.[0-9]+)+$" | awk '{printf("{\""$1"\", \""$2"\",\"\"},\n")}' | sort -u
	pnpmWithDev = []types.Library{
		{ID: "@babel/runtime@7.18.3", Name: "@babel/runtime", Version: "7.18.3", Indirect: true},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Indirect: true},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Indirect: true},
		{ID: "react@18.1.0", Name: "react", Version: "18.1.0", Indirect: false},
		{ID: "redux@4.2.0", Name: "redux", Version: "4.2.0", Indirect: false},
		{ID: "regenerator-runtime@0.13.9", Name: "regenerator-runtime", Version: "0.13.9", Indirect: true},
	}

	pnpmWithDevDeps = []types.Dependency{
		{
			ID:        "@babel/runtime@7.18.3",
			DependsOn: []string{"regenerator-runtime@0.13.9"},
		},
		{
			ID:        "loose-envify@1.4.0",
			DependsOn: []string{"js-tokens@4.0.0"},
		},
		{
			ID:        "react@18.1.0",
			DependsOn: []string{"loose-envify@1.4.0"},
		},
		{
			ID:        "redux@4.2.0",
			DependsOn: []string{"@babel/runtime@7.18.3"},
		},
	}
)
