package pom_test

import (
	"reflect"
	"testing"

	"github.com/aquasecurity/go-dep-parser/pkg/java/pom"
)

func Test_ReadSettings(t *testing.T) {
	t.Setenv("MAVEN_HOME", "testdata")
	t.Setenv("HOME", "testdata")

	s := pom.ReadSettings()

	if s.LocalRepository != "testdata/localrepo" {
		t.Errorf("LocalRepository is incorrect")
	}

	expectedOutput := []pom.Server{
		{ID: "global", Username: "", Password: ""},
		{ID: "testServerID", Username: "globalUser", Password: ""},
		{ID: "local", Username: "", Password: ""},
	}

	if !reflect.DeepEqual(s.Servers, expectedOutput) {
		t.Errorf("Servers is incorrect")
	}
}
