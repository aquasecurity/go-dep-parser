package gomod

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name bundler --rm -it ruby:2.6 bash
	// bundle init
	// bundle add dotenv json faker rubocop pry
	// bundler show | grep "*" | grep -v bundler | awk '{if(match($0, /\((.*)\)/)) printf("{\""$2"\", \""substr($0, RSTART+1, RLENGTH-2)"\"},\n");}'
	GoModNormal = []types.Library{
		{"gopkg.in/mgo.v2", "v2.0.0-20160818020120-3f83fa500528"},
		{"gopkg.in/yaml.v2", "v2.2.1"},
	}

	GoModReplace = []types.Library{
		{"/tmp/z", ""},
		{"my/xyz", "v1.3.4-me"},
	}
)
