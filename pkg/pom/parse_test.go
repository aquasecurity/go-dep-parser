package pom

import (
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	type args struct {
		r io.Reader
	}
	tests := []struct {
		name      string
		inputFile string
		want      []types.Library
		wantErr   bool
	}{
		//{
		//	name:      "cron-utils",
		//	inputFile: "testdata/cron-utils.pom",
		//	want: []types.Library{
		//		{
		//			Name:    "com.cronutils:cron-utils",
		//			Version: "9.1.2",
		//		},
		//		{
		//			Name:    "org.apache.commons:commons-lang3",
		//			Version: "3.11",
		//		},
		//		{
		//			Name:    "org.glassfish:javax.el",
		//			Version: "3.0.0",
		//		},
		//		{
		//			Name:    "org.slf4j:slf4j-api",
		//			Version: "1.7.30",
		//		},
		//	},
		//},
		//{
		//	name:      "jackson-databind",
		//	inputFile: "testdata/jackson-databind.pom",
		//	want: []types.Library{
		//		{
		//			Name:    "com.fasterxml.jackson.core:jackson-annotations",
		//			Version: "2.9.10",
		//		},
		//		{
		//			Name:    "com.fasterxml.jackson.core:jackson-core",
		//			Version: "2.9.10",
		//		},
		//		{
		//			Name:    "com.fasterxml.jackson.core:jackson-databind",
		//			Version: "2.9.10.6",
		//		},
		//	},
		//},
		{
			name:      "jenkins",
			inputFile: "testdata/jenkins/pom.xml",
			want:      []types.Library{},
		},
	}
	for _, tt := range tests {
		t.Run(path.Base(tt.inputFile), func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			p := newParser(tt.inputFile)
			got, err := p.Parse(f)
			require.NoError(t, err)

			sort.Slice(got, func(i, j int) bool {
				return got[i].Name < got[j].Name
			})

			for _, lib := range got {
				fmt.Println(lib)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_evaluateVariable(t *testing.T) {
	type args struct {
		s     string
		props map[string]string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "happy path",
			args: args{
				s: "${java.version}",
				props: map[string]string{
					"java.version": "1.7",
				},
			},
			want: "1.7",
		},
		{
			name: "two variables",
			args: args{
				s: "${foo.name}-${bar.name}",
				props: map[string]string{
					"foo.name": "aaa",
					"bar.name": "bbb",
				},
			},
			want: "aaa-bbb",
		},
		{
			name: "same variables",
			args: args{
				s: "${foo.name}-${foo.name}",
				props: map[string]string{
					"foo.name": "aaa",
				},
			},
			want: "aaa-aaa",
		},
		{
			name: "nested variables",
			args: args{
				s: "${jackson.version.core}",
				props: map[string]string{
					"jackson.version":      "2.12.1",
					"jackson.version.core": "${jackson.version}",
				},
			},
			want: "2.12.1",
		},
		{
			name: "no variable",
			args: args{
				s: "1.12",
			},
			want: "1.12",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateVariable(tt.args.s, tt.args.props)
			assert.Equal(t, tt.want, got)
		})
	}
}
