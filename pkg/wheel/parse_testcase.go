package wheel

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// listing dependencies based on METADATA files
	// docker run --name pipenv --rm -it python:3.7-alpine bash
	// pip install pipenv
	// find / -wholename "*dist-info/METADATA" | xargs -I {} sh -c "cat {} | awk  '/^Name:|^Version:|^License:/{print}' | tr -d '\n'" |  tee METADATAS
	// sed -i "s/Name: /\n/g" METADATAS && sed -i "s/Version: /:/g" METADATAS && sed -i "s/License: /:/g" METADATAS && sed '1d'
	// cat METADATAS  | awk '{split($0,a,":"); printf("{\"%s\", \"%s\", \"%s\"}\n", a[1], a[2], a[3])}' | sort | uniq

	// finding relevant metadata files for tests
	// mkdir dist-infos
	// find / -wholename "*dist-info/METADATA" | rev | cut -d '/' -f2- | rev | xargs -I % cp -r % dist-infos/
	// find dist-infos/ | grep -v METADATA | xargs rm

	// for single METADATA file with nown name
	// cat METADATA | awk  '/^Name:|^Version:|^License:/{print}' | tr -d '\n' |    \
	// sed "s/Name: /\n/g" | sed "s/Version: /:/g" | sed  "s/License: /:/g" | sed '1d' |  \
	// awk '{split($0,a,":"); printf("{\"%s\", \"%s\", \"%s\"}\n", a[1], a[2], a[3])}'
	WheelSimple = []types.Library{
		{"simple", "0.1.0", ""},
	}
	WheelDistlib = []types.Library{
		{"distlib", "0.3.1", "Python license"},
	}
	WheelVirtualenv = []types.Library{
		{"virtualenv", "20.4.2", "MIT"},
	}
)
