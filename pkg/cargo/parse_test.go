package cargo

import (
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/knqyf263/go-dep-parser/pkg/types"
	"github.com/kylelemons/godebug/pretty"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file      string // Test input file
		libraries []types.Library
	}{
		{
			file:      "testdata/cargo_normal.lock",
			libraries: CargoNormal,
		},
		{
			file:      "testdata/cargo_many.lock",
			libraries: CargoMany,
		},
		{
			file:      "testdata/cargo_nickel.lock",
			libraries: CargoNickel,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			if err != nil {
				t.Fatalf("Open() error: %v", err)
			}
			libList, err := Parse(f)
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}

			sort.Slice(libList, func(i, j int) bool {
				ret := strings.Compare(libList[i].Name, libList[j].Name)
				if ret == 0 {
					return libList[i].Version < libList[j].Version
				}
				return ret < 0
			})

			sort.Slice(v.libraries, func(i, j int) bool {
				ret := strings.Compare(v.libraries[i].Name, v.libraries[j].Name)
				if ret == 0 {
					return v.libraries[i].Version < v.libraries[j].Version
				}
				return ret < 0
			})

			if len(libList) != len(v.libraries) {
				t.Fatalf("lib length: %s", pretty.Compare(libList, v.libraries))
			}

			for i, got := range libList {
				want := v.libraries[i]
				if want.Name != got.Name {
					t.Errorf("%d: Name: got %s, want %s", i, got.Name, want.Name)
				}
				if want.Version != got.Version {
					t.Errorf("%d: Version: got %s, want %s", i, got.Version, want.Version)
				}
			}
		})
	}
}
