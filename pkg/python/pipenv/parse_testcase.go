package pipenv

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name pipenv --rm -it python:3.9-alpine sh
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	pipenvNormal = []types.Library{
		types.NewLibrary("urllib3", "1.24.2", ""),
		types.NewLibrary("requests", "2.21.0", ""),
		types.NewLibrary("pyyaml", "5.1", ""),
		types.NewLibrary("idna", "2.8", ""),
		types.NewLibrary("chardet", "3.0.4", ""),
		types.NewLibrary("certifi", "2019.3.9", ""),
	}

	// docker run --name pipenv --rm -it python:3.9-alpine bash
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml django djangorestframework
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	pipenvDjango = []types.Library{
		types.NewLibrary("urllib3", "1.24.2", ""),
		types.NewLibrary("sqlparse", "0.3.0", ""),
		types.NewLibrary("requests", "2.21.0", ""),
		types.NewLibrary("pyyaml", "5.1", ""),
		types.NewLibrary("pytz", "2019.1", ""),
		types.NewLibrary("idna", "2.8", ""),
		types.NewLibrary("djangorestframework", "3.9.3", ""),
		types.NewLibrary("django", "2.2", ""),
		types.NewLibrary("chardet", "3.0.4", ""),
		types.NewLibrary("certifi", "2019.3.9", ""),
	}

	// docker run --name pipenv --rm -it python:3.9-alpine bash
	// apk add jq
	// mkdir app && cd /app
	// pip install pipenv
	// pipenv install requests pyyaml django djangorestframework six botocore python-dateutil simplejson setuptools pyasn1 awscli jinja2
	// pipenv graph --json | jq -rc '.[] | "{\"\(.package.package_name | ascii_downcase)\", \"\(.package.installed_version)\", \"\"},"'
	pipenvMany = []types.Library{
		types.NewLibrary("urllib3", "1.24.2", ""),
		types.NewLibrary("sqlparse", "0.3.0", ""),
		types.NewLibrary("six", "1.12.0", ""),
		types.NewLibrary("simplejson", "3.16.0", ""),
		types.NewLibrary("s3transfer", "0.2.0", ""),
		types.NewLibrary("rsa", "3.4.2", ""),
		types.NewLibrary("requests", "2.21.0", ""),
		types.NewLibrary("pyyaml", "3.13", ""),
		types.NewLibrary("pytz", "2019.1", ""),
		types.NewLibrary("python-dateutil", "2.8.0", ""),
		types.NewLibrary("pyasn1", "0.4.5", ""),
		types.NewLibrary("markupsafe", "1.1.1", ""),
		types.NewLibrary("jmespath", "0.9.4", ""),
		types.NewLibrary("jinja2", "2.10.1", ""),
		types.NewLibrary("idna", "2.8", ""),
		types.NewLibrary("framework", "0.1.0", ""),
		types.NewLibrary("docutils", "0.14", ""),
		types.NewLibrary("djangorestframework", "3.9.3", ""),
		types.NewLibrary("django", "2.2", ""),
		types.NewLibrary("colorama", "0.3.9", ""),
		types.NewLibrary("chardet", "3.0.4", ""),
		types.NewLibrary("certifi", "2019.3.9", ""),
		types.NewLibrary("botocore", "1.12.137", ""),
		types.NewLibrary("awscli", "1.16.147", ""),
	}
)
