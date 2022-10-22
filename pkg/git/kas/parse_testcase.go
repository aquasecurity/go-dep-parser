package kas

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	kasRepo = []types.Library{
		{
			ID:      "github.com/org/kas@1.0.0",
			Name:    "github.com/org/kas",
			Version: "1.0.0",
		},
	}

	kasRepoLatest = []types.Library{
		{
			ID:      "github.com/org/kas@latest",
			Name:    "github.com/org/kas",
			Version: "latest",
		},
	}

	kasRepoGitUrl = []types.Library{
		{
			ID:      "github.com/org/kas@1.0.0",
			Name:    "github.com/org/kas",
			Version: "1.0.0",
		},
	}

	kasRepoSshUrl = []types.Library{
		{
			ID:      "github.com/org/kas@1.0.0",
			Name:    "github.com/org/kas",
			Version: "1.0.0",
		},
	}

	kasRepos = []types.Library{
		{
			ID:      "github.com/org/kas@1.0.0",
			Name:    "github.com/org/kas",
			Version: "1.0.0",
		},
		{
			ID:      "github.com/user/repo@2.0.0",
			Name:    "github.com/user/repo",
			Version: "2.0.0",
		},
	}
)
