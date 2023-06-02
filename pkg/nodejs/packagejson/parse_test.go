package packagejson_test

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		name      string
		inputFile string
		want      packagejson.Package
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/package.json",

			// docker run --name composer --rm -it node:12-alpine sh
			// npm init --force
			// npm install --save promise jquery
			// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
			want: packagejson.Package{
				Library: types.Library{
					ID:      "bootstrap@5.0.2",
					Name:    "bootstrap",
					Version: "5.0.2",
					License: "MIT",
				},
				Dependencies: map[string]string{
					"js-tokens": "^4.0.0",
				},
				OptionalDependencies: map[string]string{
					"colors": "^1.4.0",
				},
				DevDependencies: map[string]string{"@babel/cli": "^7.14.5", "@babel/core": "^7.14.6",
					"@babel/preset-env": "^7.14.7", "@popperjs/core": "^2.9.2",
					"@rollup/plugin-babel": "^5.3.0", "@rollup/plugin-commonjs": "^19.0.1",
					"@rollup/plugin-node-resolve": "^13.0.2", "@rollup/plugin-replace": "^3.0.0",
					"autoprefixer": "^10.2.6", "bundlewatch": "^0.3.2", "clean-css-cli": "^5.3.0",
					"cross-env": "^7.0.3", "eslint": "^7.31.0", "eslint-config-xo": "^0.36.0",
					"eslint-plugin-import": "^2.23.4", "eslint-plugin-unicorn": "^31.0.0",
					"find-unused-sass-variables": "^3.1.0", "glob": "^7.1.7", "globby": "^11.0.4",
					"hammer-simulator": "0.0.1", "hugo-bin": "^0.73.0", "ip": "^1.1.5",
					"jquery": "^3.6.0", "karma": "^6.3.4", "karma-browserstack-launcher": "1.4.0",
					"karma-chrome-launcher":            "^3.1.0",
					"karma-coverage-istanbul-reporter": "^3.0.3",
					"karma-detect-browsers":            "^2.3.3",
					"karma-firefox-launcher":           "^2.1.1", "karma-jasmine": "^4.0.1",
					"karma-jasmine-html-reporter": "^1.7.0",
					"karma-rollup-preprocessor":   "^7.0.7", "linkinator": "^2.14.0",
					"lockfile-lint": "^4.6.2", "nodemon": "^2.0.12", "npm-run-all": "^4.1.5",
					"postcss": "^8.3.5", "postcss-cli": "^8.3.1", "rollup": "^2.53.3",
					"rollup-plugin-istanbul": "^3.0.0", "rtlcss": "^3.3.0", "sass": "^1.35.2",
					"shelljs": "^0.8.4", "stylelint": "^13.13.1",
					"stylelint-config-twbs-bootstrap": "^2.2.3", "terser": "5.1.0", "vnu-jar": "21.6.11"},
			},
		},
		{
			name:      "happy path - legacy license",
			inputFile: "testdata/legacy_package.json",
			want: packagejson.Package{
				Library: types.Library{
					ID:      "angular@4.1.2",
					Name:    "angular",
					Version: "4.1.2",
					License: "ISC",
				},
				Dependencies: map[string]string{},
				DevDependencies: map[string]string{"@babel/cli": "^7.14.5", "@babel/core": "^7.14.6",
					"@babel/preset-env": "^7.14.7", "@popperjs/core": "^2.9.2",
					"@rollup/plugin-babel": "^5.3.0", "@rollup/plugin-commonjs": "^19.0.1",
					"@rollup/plugin-node-resolve": "^13.0.2", "@rollup/plugin-replace": "^3.0.0",
					"autoprefixer": "^10.2.6", "bundlewatch": "^0.3.2", "clean-css-cli": "^5.3.0",
					"cross-env": "^7.0.3", "eslint": "^7.31.0", "eslint-config-xo": "^0.36.0",
					"eslint-plugin-import": "^2.23.4", "eslint-plugin-unicorn": "^31.0.0",
					"find-unused-sass-variables": "^3.1.0", "glob": "^7.1.7", "globby": "^11.0.4",
					"hammer-simulator": "0.0.1", "hugo-bin": "^0.73.0", "ip": "^1.1.5",
					"jquery": "^3.6.0", "karma": "^6.3.4", "karma-browserstack-launcher": "1.4.0",
					"karma-chrome-launcher":            "^3.1.0",
					"karma-coverage-istanbul-reporter": "^3.0.3",
					"karma-detect-browsers":            "^2.3.3",
					"karma-firefox-launcher":           "^2.1.1", "karma-jasmine": "^4.0.1",
					"karma-jasmine-html-reporter": "^1.7.0",
					"karma-rollup-preprocessor":   "^7.0.7", "linkinator": "^2.14.0",
					"lockfile-lint": "^4.6.2", "nodemon": "^2.0.12", "npm-run-all": "^4.1.5",
					"postcss": "^8.3.5", "postcss-cli": "^8.3.1", "rollup": "^2.53.3",
					"rollup-plugin-istanbul": "^3.0.0", "rtlcss": "^3.3.0", "sass": "^1.35.2",
					"shelljs": "^0.8.4", "stylelint": "^13.13.1",
					"stylelint-config-twbs-bootstrap": "^2.2.3", "terser": "5.1.0", "vnu-jar": "21.6.11"},
			},
		},
		{
			name:      "happy path - version doesn't exist",
			inputFile: "testdata/without_version_package.json",
			want:      packagejson.Package{},
		},
		{
			name:      "sad path",
			inputFile: "testdata/invalid_package.json",

			// docker run --name composer --rm -it node:12-alpine sh
			// npm init --force
			// npm install --save promise jquery
			// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\"},\n")}'
			wantErr: "JSON decode error",
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.name), func(t *testing.T) {
			f, err := os.Open(v.inputFile)
			require.NoError(t, err)
			defer f.Close()

			got, err := packagejson.NewParser().Parse(f)
			if v.wantErr != "" {
				assert.ErrorContains(t, err, v.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, v.want, got)
		})
	}
}
