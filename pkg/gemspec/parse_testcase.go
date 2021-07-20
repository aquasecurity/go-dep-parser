package gemspec

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	RubyGemUpdate = []types.Library{
		{"rubygems-update", "3.0.3", "2-clauseBSDL,Ruby"},
	}
	JsonGem = []types.Library{
		{"json", "2.3.0", "Ruby"},
	}
	JsonVersionGem = []types.Library{
		{"json", "VERSION", "Ruby"},
	}
	JsonNameGem = []types.Library{
		{"$json", "2.3.0", "Ruby"},
	}
)
