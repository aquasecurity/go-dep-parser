package jar_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/jar"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

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

	// manually created
	jarTest = []types.Library{
		{"org.springframework:spring-core", "5.3.3"},
	}

	// manually created
	jarHeuristic = []types.Library{
		{"com.example:heuristic", "1.0.0-SNAPSHOT"},
	}
)

type apiResponse struct {
	Response response `json:"response"`
}

type response struct {
	NumFound int   `json:"numFound"`
	Docs     []doc `json:"docs"`
}

type doc struct {
	ID           string `json:"id"`
	GroupID      string `json:"g"`
	ArtifactID   string `json:"a"`
	Version      string `json:"v"`
	P            string `json:"p"`
	VersionCount int    `json:versionCount`
}

func TestParse(t *testing.T) {
	vectors := []struct {
		file string // Test input file
		want []types.Library
	}{
		{
			file: "testdata/maven.war",
			want: jarMaven,
		},
		{
			file: "testdata/gradle.war",
			want: jarGradle,
		},
		{
			file: "testdata/test.jar",
			want: jarTest,
		},
		{
			file: "testdata/heuristic-1.0.0-SNAPSHOT.jar",
			want: jarHeuristic,
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := apiResponse{
			Response: response{
				NumFound: 1,
			},
		}

		switch {
		case strings.Contains(r.URL.Query().Get("q"), "springframework"):
			res.Response.NumFound = 0
		case strings.Contains(r.URL.Query().Get("q"), "c666f5bc47eb64ed3bbd13505a26f58be71f33f0"):
			res.Response.Docs = []doc{
				{
					ID:         "org.springframework.spring-core",
					GroupID:    "org.springframework",
					ArtifactID: "spring-core",
					Version:    "5.3.3",
				},
			}
		case strings.Contains(r.URL.Query().Get("q"), "heuristic"):
			res.Response.Docs = []doc{
				{
					ID:           "org.springframework.heuristic",
					GroupID:      "org.springframework",
					ArtifactID:   "heuristic",
					VersionCount: 10,
				},
				{
					ID:           "com.example.heuristic",
					GroupID:      "com.example",
					ArtifactID:   "heuristic",
					VersionCount: 100,
				},
			}
		}
		_ = json.NewEncoder(w).Encode(res)
	}))

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, err := jar.Parse(f, jar.WithURL(ts.URL), jar.WithFilePath(v.file))
			require.NoError(t, err)

			sort.Slice(got, func(i, j int) bool {
				return got[i].Name < got[j].Name
			})
			sort.Slice(v.want, func(i, j int) bool {
				return v.want[i].Name < v.want[j].Name
			})

			assert.Equal(t, v.want, got)
		})
	}
}
