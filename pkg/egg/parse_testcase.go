package egg

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// listing dependencies based on egg-info or PKG-INFO files
	// docker run --name poetry --rm -it jonatkinson/python-poetry:3.7 bash
	// find / -wholename "*egg-info" | xargs -I {} sh -c 'cat {} | awk 'NR==2,NR==3'' | tee PKG-INFOS
	// find / -wholename "*egg-info/PKG-INFO" | xargs -I {} sh -c 'cat {} | awk 'NR==2,NR==3'' | tee -a PKG-INFOS
	// cat PKG-INFOS | awk 'BEGIN {FS=" "} {print $2}' | awk '!(NR%2){printf("{\""p"\", \""$0"\"},\n")}{p=$0}' | sort | uniq

	// copying relevant metadata files for tests
	// mkdir egg-infos
	// find / -name "*egg-info" | xargs -I % cp -r % egg-infos/
	// find egg-infos/ | grep txt | xargs rm
	EggNormal = []types.Library{
		{"Python", "2.7.13"},
		{"argparse", "1.2.1"},
		{"bzr", "2.8.0dev1"},
		{"configobj", "5.0.6"},
		{"mercurial", "4.0"},
		{"six", "1.10.0"},
		{"wsgiref", "0.1.2"},
	}

	// listing dependencies based on egg-info or PKG-INFO files
	// docker run --name poetry --rm -it jonatkinson/python-poetry:3.7 bash
	// poetry new repo && cd repo
	// poetry add requests pyyaml botocore python-dateutil simplejson setuptools pyasn1 awscli jinja2
	// find / -wholename "*egg-info" | xargs -I {} sh -c 'cat {} | awk 'NR==2,NR==3'' | tee PKG-INFOS
	// find / -wholename "*egg-info/PKG-INFO" | xargs -I {} sh -c 'cat {} | awk 'NR==2,NR==3'' | tee -a PKG-INFOS
	// cat PKG-INFOS | awk 'BEGIN {FS=" "} {print $2}' | awk '!(NR%2){printf("{\""p"\", \""$0"\"},\n")}{p=$0}' | sort | uniq

	// copying relevant metadata files for tests
	// mkdir egg-infos
	// find / -name "*egg-info" | xargs -I % cp -r % egg-infos/
	// find egg-infos/ | grep txt | xargs rm
	EggMany = []types.Library{
		{"Python", "2.7.13"},
		{"argparse", "1.2.1"},
		{"awscli", "1.19.12"},
		{"bzr", "2.8.0dev1"},
		{"configobj", "5.0.6"},
		{"mercurial", "4.0"},
		{"six", "1.10.0"},
		{"wsgiref", "0.1.2"},
	}

	// listing dependencies based on egg-info or PKG-INFO files
	// docker run --name poetry --rm -it jonatkinson/python-poetry:3.7 bash
	// poetry new repo && cd repo
	// poetry add requests pyyaml django djangorestframework
	// find / -wholename "*egg-info" | xargs -I {} sh -c 'cat {} | awk 'NR==2,NR==3'' | tee PKG-INFOS
	// find / -wholename "*egg-info/PKG-INFO" | xargs -I {} sh -c 'cat {} | awk 'NR==2,NR==3'' | tee -a PKG-INFOS
	// cat PKG-INFOS | awk 'BEGIN {FS=" "} {print $2}' | awk '!(NR%2){printf("{\""p"\", \""$0"\"},\n")}{p=$0}' | sort | uniq

	// copying relevant metadata files for tests
	// mkdir egg-infos
	// find / -name "*egg-info" | xargs -I % cp -r % egg-infos/
	// find egg-infos/ | grep txt | xargs rm
	EggDjango = []types.Library{
		{"Python", "2.7.13"},
		{"argparse", "1.2.1"},
		{"bzr", "2.8.0dev1"},
		{"configobj", "5.0.6"},
		{"mercurial", "4.0"},
		{"six", "1.10.0"},
		{"wsgiref", "0.1.2"},
	}
)
