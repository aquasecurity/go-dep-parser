package include

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	gitlabCiInclude = []types.Library{
		{
			ID:      "my-group/my-project@1.0.0",
			Name:    "my-group/my-project",
			Version: "1.0.0",
		},
	}

	gitlabCiIncludeLatest = []types.Library{
		{
			ID:      "my-group/my-project@latest",
			Name:    "my-group/my-project",
			Version: "latest",
		},
	}
)
