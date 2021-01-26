package jar

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// cd testdata/testimage/maven && docker build -t test .
	// docker run --rm --name test -it test bash
	// mvn dependency:tree -Dscope=compile | awk '/:tree/,/BUILD SUCCESS/' | awk 'NR > 1 { print }' | head -n -2 | awk '{print $NF}' | awk -F":" '{printf("{\""$1":"$2"\", \""$4 "\"},\n")}'
	jarMaven = []types.Library{
		{"com.example:web-app", "1.0-SNAPSHOT"},
		{"com.fasterxml.jackson.core:jackson-databind", "2.9.10.6"},
		{"com.fasterxml.jackson.core:jackson-annotations", "2.9.10"},
		{"com.fasterxml.jackson.core:jackson-core", "2.9.10"},
		{"com.cronutils:cron-utils", "9.1.2"},
		{"org.slf4j:slf4j-api", "1.7.30"},
		{"org.glassfish:javax.el", "3.0.0"},
		{"org.apache.commons:commons-lang3", "3.11"},
	}

	// cd testdata/testimage/gradle && docker build -t test .
	// docker run --rm --name test -it test bash
	// gradle app:dependencies --configuration implementation | grep "[+\]---" | cut -d" " -f2 | awk -F":" '{printf("{\""$1":"$2"\", \""$3"\"},\n")}'
	jarGradle = []types.Library{
		{"commons-dbcp:commons-dbcp", "1.4"},
		{"commons-pool:commons-pool", "1.6"},
		{"log4j:log4j", "1.2.17"},
		{"org.apache.commons:commons-compress", "1.19"},
	}
)
