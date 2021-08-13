package pymetadata

import (
	"os"
	"path"
	"testing"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file string // Test input file
		want []types.Library
	}{
		// listing dependencies based on METADATA/PKG-INFO files
		// docker run --name pipenv --rm -it python:3.7-alpine /bin/sh
		// pip install pipenv
		// find / -wholename "*(dist-info/METADATA|.egg-info/PKG-INFO)" | xargs -I {} sh -c 'cat {} | grep -e "^Name:" -e "^Version:" -e "^License:"' | tee METADATAS
		// cat METADATAS | cut -d" " -f2- | tr "\n" "\t" | awk -F "\t" '{for(i=1;i<=NF;i=i+3){printf "\{\""$i"\", \""$(i+1)"\", \""$(i+2)"\"\}\n"}}'

		{
			file: "testdata/setuptools-51.3.3-py3.8.egg-info.PKG-INFO",

			// docker run --name python --rm -it python:3.9-alpine sh
			// apk add py3-setuptools
			// cd /usr/lib/python3.9/site-packages/setuptools-52.0.0-py3.9.egg-info/
			// cat PKG-INFO | grep -e "^Name:" -e "^Version:" -e "^License:" | cut -d" " -f2- | \
			// tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\", \""$2"\", \""$3"\"\}\n")}'
			want: []types.Library{
				{"setuptools", "51.3.3", "UNKNOWN"},
			},
		},
		{
			file: "testdata/six-1.15.0-py3.8.egg-info",

			// docker run --name python --rm -it python:3.9-alpine sh
			// apk add py3-setuptools
			// cd /usr/lib/python3.9/site-packages/
			// cat six-1.15.0-py3.9.egg-info | grep -e "^Name:" -e "^Version:" -e "^License:" | cut -d" " -f2- | \
			// tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\", \""$2"\", \""$3"\"\}\n")}'
			want: []types.Library{
				{"six", "1.15.0", "MIT"},
			},
		},
		{
			file: "testdata/distlib-0.3.1-py3.9.egg-info",

			// docker run --name python --rm -it python:3.9-alpine sh
			// apk add py3-distlib
			// cd /usr/lib/python3.9/site-packages/
			// cat distlib-0.3.1-py3.9.egg-info | grep -e "^Name:" -e "^Version:" -e "^License:" | cut -d" " -f2- | \
			// tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\", \""$2"\", \""$3"\"\}\n")}'
			want: []types.Library{
				{"distlib", "0.3.1", "Python license"},
			},
		},
		{

			// finding relevant metadata files for tests
			// mkdir dist-infos
			// find / -wholename "*dist-info/METADATA" | rev | cut -d '/' -f2- | rev | xargs -I % cp -r % dist-infos/
			// find dist-infos/ | grep -v METADATA | xargs rm -R

			// for single METADATA file with known name
			// cat "{{ libname }}.METADATA | grep -e "^Name:" -e "^Version:" -e "^License:" | cut -d" " -f2- | tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\", \""$2"\", \""$3"\"\}\n")}'
			file: "testdata/simple-0.1.0.METADATA",
			want: []types.Library{
				{"simple", "0.1.0", ""},
			},
		},
		{
			// for single METADATA file with known name
			// cat "{{ libname }}.METADATA | grep -e "^Name:" -e "^Version:" -e "^License:" | cut -d" " -f2- | tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\", \""$2"\", \""$3"\"\}\n")}'
			file: "testdata/distlib-0.3.1.METADATA",
			want: []types.Library{
				{"distlib", "0.3.1", "Python license"},
			},
		},
		{
			// for single METADATA file with known name
			// cat "{{ libname }}.METADATA | grep -e "^Name:" -e "^Version:" -e "^License:" | cut -d" " -f2- | tr "\n" "\t" | awk -F "\t" '{printf("\{\""$1"\", \""$2"\", \""$3"\"\}\n")}'
			file: "testdata/virtualenv-20.4.2.METADATA",
			want: []types.Library{
				{"virtualenv", "20.4.2", "MIT"},
			},
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, err := Parse(f)
			require.NoError(t, err)

			assert.Equal(t, v.want, got)
		})
	}
}
