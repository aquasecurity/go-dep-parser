package wheel

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// listing dependencies based on METADATA files
	// docker run --name pipenv --rm -it python:3.7-alpine bash
	// pip install pipenv
	// find / -wholename "*dist-info/METADATA" | xargs -I {} sh -c 'cat {} | awk 'NR==2,NR==3'' | tee METADATAS
	// cat METADATAS | awk 'BEGIN {FS=" "} {print $2}' | awk '!(NR%2){printf("{\""p"\", \""$0"\"},\n")}{p=$0}' | sort | uniq

	// copying relevant metadata files for tests
	// mkdir dist-infos
	// find / -wholename "*dist-info/METADATA" | rev | cut -d '/' -f2- | rev | xargs -I % cp -r % dist-infos/
	// find dist-infos/ | grep -v METADATA | xargs rm
	WheelNormal = []types.Library{
		{"appdirs", "1.4.4"},
		{"certifi", "2020.12.5"},
		{"distlib", "0.3.1"},
		{"filelock", "3.0.12"},
		{"importlib-metadata", "3.4.0"},
		{"pip", "21.0.1"},
		{"pipenv", "2020.11.15"},
		{"setuptools", "53.0.0"},
		{"six", "1.15.0"},
		{"typing-extensions", "3.7.4.3"},
		{"virtualenv", "20.4.2"},
		{"virtualenv-clone", "0.5.4"},
		{"wheel", "0.36.2"},
		{"zipp", "3.4.0"},
	}

	// listing dependencies based on METADATA files
	// docker run --name pipenv --rm -it python:3.7-alpine bash
	// pip install pipenv
	// mkdir app && cd app
	// pipenv install requests pyyaml botocore python-dateutil simplejson setuptools pyasn1 awscli jinja2
	// find / -wholename "*dist-info/METADATA" | xargs -I {} sh -c 'cat {} | awk 'NR==2,NR==3'' | tee METADATAS
	// cat METADATAS | awk 'BEGIN {FS=" "} {print $2}' | awk '!(NR%2){printf("{\""p"\", \""$0"\"},\n")}{p=$0}' | sort | uniq

	// copying relevant metadata files
	// mkdir dist-infos
	// find / -wholename "*dist-info/METADATA" | rev | cut -d '/' -f2- | rev | xargs -I % cp -r % dist-infos/
	// find dist-infos/ | grep -v METADATA | xargs rm
	WheelMany = []types.Library{
		{"Jinja2", "2.11.3"},
		{"MarkupSafe", "1.1.1"},
		{"PyYAML", "5.4.1"},
		{"appdirs", "1.4.4"},
		{"awscli", "1.19.12"},
		{"botocore", "1.20.12"},
		{"certifi", "2020.12.5"},
		{"chardet", "4.0.0"},
		{"colorama", "0.4.3"},
		{"distlib", "0.3.1"},
		{"docutils", "0.15.2"},
		{"filelock", "3.0.12"},
		{"idna", "2.10"},
		{"importlib-metadata", "3.4.0"},
		{"jmespath", "0.10.0"},
		{"pip", "21.0.1"},
		{"pipenv", "2020.11.15"},
		{"pyasn1", "0.4.8"},
		{"python-dateutil", "2.8.1"},
		{"requests", "2.25.1"},
		{"rsa", "4.5"},
		{"s3transfer", "0.3.4"},
		{"setuptools", "52.0.0"},
		{"setuptools", "53.0.0"},
		{"simplejson", "3.17.2"},
		{"six", "1.15.0"},
		{"typing-extensions", "3.7.4.3"},
		{"urllib3", "1.26.3"},
		{"virtualenv", "20.4.2"},
		{"virtualenv-clone", "0.5.4"},
		{"wheel", "0.36.2"},
		{"zipp", "3.4.0"},
	}

	// listing dependencies based on METADATA files
	// docker run --name pipenv --rm -it python:3.7-alpine bash
	// pip install pipenv
	// mkdir app && cd app
	// pipenv install requests pyyaml django djangorestframework
	// find / -wholename "*dist-info/METADATA" | xargs -I {} sh -c 'cat {} | awk 'NR==2,NR==3'' | tee METADATAS
	// cat METADATAS | awk 'BEGIN {FS=" "} {print $2}' | awk '!(NR%2){printf("{\""p"\", \""$0"\"},\n")}{p=$0}' | sort | uniq

	// copying relevant metadata files
	// mkdir dist-infos
	// find / -wholename "*dist-info/METADATA" | rev | cut -d '/' -f2- | rev | xargs -I % cp -r % dist-infos/
	// find dist-infos/ | grep -v METADATA | xargs rm
	WheelDjango = []types.Library{
		{"Django", "3.1.7"},
		{"PyYAML", "5.4.1"},
		{"appdirs", "1.4.4"},
		{"asgiref", "3.3.1"},
		{"certifi", "2020.12.5"},
		{"chardet", "4.0.0"},
		{"distlib", "0.3.1"},
		{"djangorestframework", "3.12.2"},
		{"filelock", "3.0.12"},
		{"idna", "2.10"},
		{"importlib-metadata", "3.4.0"},
		{"pip", "21.0.1"},
		{"pipenv", "2020.11.15"},
		{"pytz", "2021.1"},
		{"requests", "2.25.1"},
		{"setuptools", "52.0.0"},
		{"setuptools", "53.0.0"},
		{"six", "1.15.0"},
		{"sqlparse", "0.4.1"},
		{"typing-extensions", "3.7.4.3"},
		{"urllib3", "1.26.3"},
		{"virtualenv", "20.4.2"},
		{"virtualenv-clone", "0.5.4"},
		{"wheel", "0.36.2"},
		{"zipp", "3.4.0"},
	}
)
