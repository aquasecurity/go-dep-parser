package composer

import (
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"sort"
	"strings"
	"testing"
)

var (
	// docker run --name composer --rm -it composer@sha256:082ed124b68e7e880721772a6bf22ad809e3bc87db8bbee9f0ec7127bb21ccad bash
	// apk add jq
	// composer require laravel/installer
	// composer require pear/log --dev
	// composer show -i --no-dev -f json | jq --sort-keys -rc '.installed[] | "{ID: \"\(.name)@\(.version)\", Name: \"\(.name)\", Version: \"\(.version)\", License: \"\", Locations: []types.Location{{StartLine: , EndLine: }}},"'
	// locations are filled manually
	composerLibs = []types.Library{
		{ID: "laravel/installer@v4.4.3", Name: "laravel/installer", Version: "v4.4.3", License: "MIT", Locations: []types.Location{{StartLine: 9, EndLine: 65}}},
		{ID: "psr/container@2.0.2", Name: "psr/container", Version: "2.0.2", License: "MIT", Locations: []types.Location{{StartLine: 66, EndLine: 118}}},
		{ID: "symfony/console@v6.2.7", Name: "symfony/console", Version: "v6.2.7", License: "MIT", Locations: []types.Location{{StartLine: 119, EndLine: 214}}},
		{ID: "symfony/deprecation-contracts@v3.2.1", Name: "symfony/deprecation-contracts", Version: "v3.2.1", License: "MIT", Locations: []types.Location{{StartLine: 215, EndLine: 281}}},
		{ID: "symfony/polyfill-ctype@v1.27.0", Name: "symfony/polyfill-ctype", Version: "v1.27.0", License: "MIT", Locations: []types.Location{{StartLine: 282, EndLine: 363}}},
		{ID: "symfony/polyfill-intl-grapheme@v1.27.0", Name: "symfony/polyfill-intl-grapheme", Version: "v1.27.0", License: "MIT", Locations: []types.Location{{StartLine: 364, EndLine: 444}}},
		{ID: "symfony/polyfill-intl-normalizer@v1.27.0", Name: "symfony/polyfill-intl-normalizer", Version: "v1.27.0", License: "MIT", Locations: []types.Location{{StartLine: 445, EndLine: 528}}},
		{ID: "symfony/polyfill-mbstring@v1.27.0", Name: "symfony/polyfill-mbstring", Version: "v1.27.0", License: "MIT", Locations: []types.Location{{StartLine: 529, EndLine: 611}}},
		{ID: "symfony/process@v6.2.7", Name: "symfony/process", Version: "v6.2.7", License: "MIT", Locations: []types.Location{{StartLine: 612, EndLine: 672}}},
		{ID: "symfony/service-contracts@v3.2.1", Name: "symfony/service-contracts", Version: "v3.2.1", License: "MIT", Locations: []types.Location{{StartLine: 673, EndLine: 757}}},
		{ID: "symfony/string@v6.2.7", Name: "symfony/string", Version: "v6.2.7", License: "MIT", Locations: []types.Location{{StartLine: 758, EndLine: 843}}},
	}
	// dependencies are filled manually
	composerDeps = []types.Dependency{
		{ID: "laravel/installer@v4.4.3", DependsOn: []string{"symfony/console@v6.2.7", "symfony/process@v6.2.7"}},
		{ID: "symfony/console@v6.2.7", DependsOn: []string{"symfony/deprecation-contracts@v3.2.1", "symfony/polyfill-mbstring@v1.27.0", "symfony/service-contracts@v3.2.1", "symfony/string@v6.2.7"}},
		{ID: "symfony/service-contracts@v3.2.1", DependsOn: []string{"psr/container@2.0.2"}},
		{ID: "symfony/string@v6.2.7", DependsOn: []string{"symfony/polyfill-ctype@v1.27.0", "symfony/polyfill-intl-grapheme@v1.27.0", "symfony/polyfill-intl-normalizer@v1.27.0", "symfony/polyfill-mbstring@v1.27.0"}},
	}
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantLibs []types.Library
		wantDeps []types.Dependency
	}{
		{
			name:     "happy path",
			file:     "testdata/composer_happy.lock",
			wantLibs: composerLibs,
			wantDeps: composerDeps,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, deps, err := NewParser().Parse(f)
			require.NoError(t, err)

			sortLibs(got)
			sortDeps(deps)

			assert.Equal(t, tt.wantLibs, got)
			assert.Equal(t, tt.wantDeps, deps)
		})
	}
}

func sortDeps(deps []types.Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		return strings.Compare(deps[i].ID, deps[j].ID) < 0
	})

	for i := range deps {
		sort.Strings(deps[i].DependsOn)
	}
}

func sortLibs(libs []types.Library) {
	sort.Slice(libs, func(i, j int) bool {
		return strings.Compare(libs[i].ID, libs[j].ID) < 0
	})
}
