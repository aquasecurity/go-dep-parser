package pip

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	requirementsFlask = []types.Library{
		types.NewLibrary("click", "8.0.0", ""),
		types.NewLibrary("Flask", "2.0.0", ""),
		types.NewLibrary("itsdangerous", "2.0.0", ""),
		types.NewLibrary("Jinja2", "3.0.0", ""),
		types.NewLibrary("MarkupSafe", "2.0.0", ""),
		types.NewLibrary("Werkzeug", "2.0.0", ""),
	}

	requirementsComments = []types.Library{
		types.NewLibrary("click", "8.0.0", ""),
		types.NewLibrary("Flask", "2.0.0", ""),
		types.NewLibrary("Jinja2", "3.0.0", ""),
		types.NewLibrary("MarkupSafe", "2.0.0", ""),
	}

	requirementsSpaces = []types.Library{
		types.NewLibrary("click", "8.0.0", ""),
		types.NewLibrary("Flask", "2.0.0", ""),
		types.NewLibrary("itsdangerous", "2.0.0", ""),
		types.NewLibrary("Jinja2", "3.0.0", ""),
	}

	requirementsNoVersion = []types.Library{
		types.NewLibrary("Flask", "2.0.0", ""),
	}

	requirementsOperator = []types.Library{
		types.NewLibrary("Django", "2.3.4", ""),
		types.NewLibrary("SomeProject", "5.4", ""),
	}

	requirementsHash = []types.Library{
		types.NewLibrary("FooProject", "1.2", ""),
		types.NewLibrary("Jinja2", "3.0.0", ""),
	}

	requirementsHyphens = []types.Library{
		types.NewLibrary("oauth2-client", "4.0.0", ""),
		types.NewLibrary("python-gitlab", "2.0.0", ""),
	}
)
