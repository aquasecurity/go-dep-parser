package python

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name pipenv --rm -it python:3.7-alpine bash
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\"},"'
	requirementsFlask = []types.Library{
		{"click", "8.0.0"},
		{"Flask", "2.0.0"},
		{"itsdangerous", "2.0.0"},
		{"Jinja2", "3.0.0"},
		{"MarkupSafe", "2.0.0"},
		{"Werkzeug", "2.0.0"},
	}
)
