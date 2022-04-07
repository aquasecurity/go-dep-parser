package poetry

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name pipenv --rm -it python:3.9-alpine sh
	// apk add curl
	// curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
	// export PATH=/root/.poetry/bin/:$PATH
	// poetry new normal && cd normal
	// poetry add pypi
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{\""$1"\", \""$2"\", \"\"},\n") }'
	poetryNormal = []types.Library{
		types.NewLibrary("atomicwrites", "1.3.0", ""),
		types.NewLibrary("attrs", "19.1.0", ""),
		types.NewLibrary("colorama", "0.4.1", ""),
		types.NewLibrary("more-itertools", "7.0.0", ""),
		types.NewLibrary("pluggy", "0.11.0", ""),
		types.NewLibrary("py", "1.8.0", ""),
		types.NewLibrary("pypi", "2.1", ""),
		types.NewLibrary("pytest", "3.10.1", ""),
		types.NewLibrary("six", "1.12.0", ""),
	}

	// docker run --name pipenv --rm -it python:3.9-alpine sh
	// apk add curl
	// curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
	// export PATH=/root/.poetry/bin/:$PATH
	// Use https://github.com/sdispater/poetry/blob/master/poetry.lock
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{\""$1"\", \""$2"\", \"\"},\n") }'
	poetryMany = []types.Library{
		types.NewLibrary("appdirs", "1.4.3", ""),
		types.NewLibrary("aspy.yaml", "1.2.0", ""),
		types.NewLibrary("atomicwrites", "1.3.0", ""),
		types.NewLibrary("attrs", "19.1.0", ""),
		types.NewLibrary("black", "19.3b0", ""),
		types.NewLibrary("cachecontrol", "0.12.5", ""),
		types.NewLibrary("cachy", "0.2.0", ""),
		types.NewLibrary("certifi", "2019.3.9", ""),
		types.NewLibrary("cfgv", "1.6.0", ""),
		types.NewLibrary("chardet", "3.0.4", ""),
		types.NewLibrary("cleo", "0.6.8", ""),
		types.NewLibrary("click", "7.0", ""),
		types.NewLibrary("colorama", "0.4.1", ""),
		types.NewLibrary("configparser", "3.7.4", ""),
		types.NewLibrary("contextlib2", "0.5.5", ""),
		types.NewLibrary("coverage", "4.5.3", ""),
		types.NewLibrary("enum34", "1.1.6", ""),
		types.NewLibrary("filelock", "3.0.10", ""),
		types.NewLibrary("funcsigs", "1.0.2", ""),
		types.NewLibrary("functools32", "3.2.3-2", ""),
		types.NewLibrary("futures", "3.2.0", ""),
		types.NewLibrary("glob2", "0.6", ""),
		types.NewLibrary("html5lib", "1.0.1", ""),
		types.NewLibrary("httpretty", "0.9.6", ""),
		types.NewLibrary("identify", "1.4.3", ""),
		types.NewLibrary("idna", "2.8", ""),
		types.NewLibrary("importlib-metadata", "0.12", ""),
		types.NewLibrary("importlib-resources", "1.0.2", ""),
		types.NewLibrary("jinja2", "2.10.1", ""),
		types.NewLibrary("jsonschema", "3.0.1", ""),
		types.NewLibrary("livereload", "2.6.1", ""),
		types.NewLibrary("lockfile", "0.12.2", ""),
		types.NewLibrary("markdown", "3.0.1", ""),
		types.NewLibrary("markdown", "3.1", ""),
		types.NewLibrary("markupsafe", "1.1.1", ""),
		types.NewLibrary("mkdocs", "1.0.4", ""),
		types.NewLibrary("mock", "3.0.5", ""),
		types.NewLibrary("more-itertools", "5.0.0", ""),
		types.NewLibrary("more-itertools", "7.0.0", ""),
		types.NewLibrary("msgpack", "0.6.1", ""),
		types.NewLibrary("nodeenv", "1.3.3", ""),
		types.NewLibrary("packaging", "19.0", ""),
		types.NewLibrary("pastel", "0.1.0", ""),
		types.NewLibrary("pathlib2", "2.3.3", ""),
		types.NewLibrary("pkginfo", "1.5.0.1", ""),
		types.NewLibrary("pluggy", "0.11.0", ""),
		types.NewLibrary("pre-commit", "1.16.1", ""),
		types.NewLibrary("py", "1.8.0", ""),
		types.NewLibrary("pygments", "2.3.1", ""),
		types.NewLibrary("pygments", "2.4.0", ""),
		types.NewLibrary("pygments-github-lexers", "0.0.5", ""),
		types.NewLibrary("pylev", "1.3.0", ""),
		types.NewLibrary("pymdown-extensions", "6.0", ""),
		types.NewLibrary("pyparsing", "2.4.0", ""),
		types.NewLibrary("pyrsistent", "0.14.11", ""),
		types.NewLibrary("pytest", "4.5.0", ""),
		types.NewLibrary("pytest-cov", "2.7.1", ""),
		types.NewLibrary("pytest-mock", "1.10.4", ""),
		types.NewLibrary("pytest-sugar", "0.9.2", ""),
		types.NewLibrary("pyyaml", "5.1", ""),
		types.NewLibrary("requests", "2.21.0", ""),
		types.NewLibrary("requests", "2.22.0", ""),
		types.NewLibrary("requests-toolbelt", "0.8.0", ""),
		types.NewLibrary("scandir", "1.10.0", ""),
		types.NewLibrary("shellingham", "1.3.1", ""),
		types.NewLibrary("six", "1.12.0", ""),
		types.NewLibrary("termcolor", "1.1.0", ""),
		types.NewLibrary("toml", "0.10.0", ""),
		types.NewLibrary("tomlkit", "0.5.3", ""),
		types.NewLibrary("tornado", "5.1.1", ""),
		types.NewLibrary("tox", "3.11.1", ""),
		types.NewLibrary("typing", "3.6.6", ""),
		types.NewLibrary("urllib3", "1.24.3", ""),
		types.NewLibrary("urllib3", "1.25.2", ""),
		types.NewLibrary("virtualenv", "16.6.0", ""),
		types.NewLibrary("wcwidth", "0.1.7", ""),
		types.NewLibrary("webencodings", "0.5.1", ""),
		types.NewLibrary("zipp", "0.5.1", ""),
	}

	// docker run --name pipenv --rm -it python:3.9-alpine sh
	// apk add curl
	// curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
	// export PATH=/root/.poetry/bin/:$PATH
	// poetry new web && cd web
	// poetry add flask
	// poetry show -a | awk '{gsub(/\(!\)/, ""); printf("{\""$1"\", \""$2"\", \"\"},\n") }'
	poetryFlask = []types.Library{
		types.NewLibrary("atomicwrites", "1.3.0", ""),
		types.NewLibrary("attrs", "19.1.0", ""),
		types.NewLibrary("click", "7.0", ""),
		types.NewLibrary("colorama", "0.4.1", ""),
		types.NewLibrary("flask", "1.0.3", ""),
		types.NewLibrary("itsdangerous", "1.1.0", ""),
		types.NewLibrary("jinja2", "2.10.1", ""),
		types.NewLibrary("markupsafe", "1.1.1", ""),
		types.NewLibrary("more-itertools", "7.0.0", ""),
		types.NewLibrary("pluggy", "0.11.0", ""),
		types.NewLibrary("py", "1.8.0", ""),
		types.NewLibrary("pytest", "3.10.1", ""),
		types.NewLibrary("six", "1.12.0", ""),
		types.NewLibrary("werkzeug", "0.15.4", ""),
	}
)
