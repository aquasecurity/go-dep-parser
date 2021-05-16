package python

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	requirementsFlask = []types.Library{
		{"click", "8.0.0"},
		{"Flask", "2.0.0"},
		{"itsdangerous", "2.0.0"},
		{"Jinja2", "3.0.0"},
		{"MarkupSafe", "2.0.0"},
		{"Werkzeug", "2.0.0"},
	}
)
