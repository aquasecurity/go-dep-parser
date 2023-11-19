package pip

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	requirementsFlask = []types.Library{
		{Name: "click", Version: "8.0.0", Locations: []types.Location{{StartLine: 1, EndLine: 1}}},
		{Name: "Flask", Version: "2.0.0", Locations: []types.Location{{StartLine: 2, EndLine: 2}}},
		{Name: "itsdangerous", Version: "2.0.0", Locations: []types.Location{{StartLine: 3, EndLine: 3}}},
		{Name: "Jinja2", Version: "3.0.0", Locations: []types.Location{{StartLine: 4, EndLine: 4}}},
		{Name: "MarkupSafe", Version: "2.0.0", Locations: []types.Location{{StartLine: 5, EndLine: 5}}},
		{Name: "Werkzeug", Version: "2.0.0", Locations: []types.Location{{StartLine: 6, EndLine: 6}}},
	}

	requirementsComments = []types.Library{
		{Name: "click", Version: "8.0.0", Locations: []types.Location{{StartLine: 4, EndLine: 4}}},
		{Name: "Flask", Version: "2.0.0", Locations: []types.Location{{StartLine: 5, EndLine: 5}}},
		{Name: "Jinja2", Version: "3.0.0", Locations: []types.Location{{StartLine: 6, EndLine: 6}}},
		{Name: "MarkupSafe", Version: "2.0.0", Locations: []types.Location{{StartLine: 7, EndLine: 7}}},
	}

	requirementsSpaces = []types.Library{
		{Name: "click", Version: "8.0.0", Locations: []types.Location{{StartLine: 1, EndLine: 1}}},
		{Name: "Flask", Version: "2.0.0", Locations: []types.Location{{StartLine: 2, EndLine: 2}}},
		{Name: "itsdangerous", Version: "2.0.0", Locations: []types.Location{{StartLine: 3, EndLine: 3}}},
		{Name: "Jinja2", Version: "3.0.0", Locations: []types.Location{{StartLine: 5, EndLine: 5}}},
	}

	requirementsNoVersion = []types.Library{
		{Name: "Flask", Version: "2.0.0", Locations: []types.Location{{StartLine: 1, EndLine: 1}}},
	}

	requirementsOperator = []types.Library{
		{Name: "Django", Version: "2.3.4", Locations: []types.Location{{StartLine: 4, EndLine: 4}}},
		{Name: "SomeProject", Version: "5.4", Locations: []types.Location{{StartLine: 5, EndLine: 5}}},
	}

	requirementsHash = []types.Library{
		{Name: "FooProject", Version: "1.2", Locations: []types.Location{{StartLine: 1, EndLine: 1}}},
		{Name: "Jinja2", Version: "3.0.0", Locations: []types.Location{{StartLine: 4, EndLine: 4}}},
	}

	requirementsHyphens = []types.Library{
		{Name: "oauth2-client", Version: "4.0.0", Locations: []types.Location{{StartLine: 1, EndLine: 1}}},
		{Name: "python-gitlab", Version: "2.0.0", Locations: []types.Location{{StartLine: 2, EndLine: 2}}},
	}

	requirementsExtras = []types.Library{
		{Name: "pyjwt", Version: "2.1.0", Locations: []types.Location{{StartLine: 1, EndLine: 1}}},
		{Name: "celery", Version: "4.4.7", Locations: []types.Location{{StartLine: 2, EndLine: 2}}},
	}

	requirementsUtf16le = []types.Library{
		{Name: "attrs", Version: "20.3.0", Locations: []types.Location{{StartLine: 1, EndLine: 1}}},
	}
)
