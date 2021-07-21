package packagejson

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name composer --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save promise jquery
	// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
	NpmNormal = []types.Library{
		{"bootstrap", "5.0.2", "MIT"},
	}
)
