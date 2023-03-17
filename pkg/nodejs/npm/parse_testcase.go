package npm

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name node --rm -it node@sha256:51dd437f31812df71108b81385e2945071ec813d5815fa3403855669c8f3432b sh
	// mkdir node_v1 && cd node_v1
	// npm init --force
	// npm install --save finalhandler@1.1.1 body-parser@1.18.3 ms@1.0.0 @babel/helper-string-parser@7.19.4
	// npm install --save-dev debug@2.5.2
	// npm i --lockfile-version 1
	// libraries are filled manually

	npmV1Libs = []types.Library{
		{ID: "@babel/helper-string-parser@7.19.4", Name: "@babel/helper-string-parser", Version: "7.19.4", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/@babel/helper-string-parser/-/helper-string-parser-7.19.4.tgz"}}, Locations: []types.Location{{StartLine: 7, EndLine: 11}}},
		{ID: "body-parser@1.18.3", Name: "body-parser", Version: "1.18.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/body-parser/-/body-parser-1.18.3.tgz"}}, Locations: []types.Location{{StartLine: 12, EndLine: 43}}},
		{ID: "bytes@3.0.0", Name: "bytes", Version: "3.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/bytes/-/bytes-3.0.0.tgz"}}, Locations: []types.Location{{StartLine: 44, EndLine: 48}}},
		{ID: "content-type@1.0.5", Name: "content-type", Version: "1.0.5", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/content-type/-/content-type-1.0.5.tgz"}}, Locations: []types.Location{{StartLine: 49, EndLine: 53}}},
		{ID: "debug@2.6.9", Name: "debug", Version: "2.6.9", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz"}}, Locations: []types.Location{{StartLine: 29, EndLine: 36}, {StartLine: 105, EndLine: 112}}},
		{ID: "depd@1.1.2", Name: "depd", Version: "1.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/depd/-/depd-1.1.2.tgz"}}, Locations: []types.Location{{StartLine: 71, EndLine: 75}}},
		{ID: "ee-first@1.1.1", Name: "ee-first", Version: "1.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ee-first/-/ee-first-1.1.1.tgz"}}, Locations: []types.Location{{StartLine: 76, EndLine: 80}}},
		{ID: "encodeurl@1.0.2", Name: "encodeurl", Version: "1.0.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/encodeurl/-/encodeurl-1.0.2.tgz"}}, Locations: []types.Location{{StartLine: 81, EndLine: 85}}},
		{ID: "escape-html@1.0.3", Name: "escape-html", Version: "1.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/escape-html/-/escape-html-1.0.3.tgz"}}, Locations: []types.Location{{StartLine: 86, EndLine: 90}}},
		{ID: "finalhandler@1.1.1", Name: "finalhandler", Version: "1.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/finalhandler/-/finalhandler-1.1.1.tgz"}}, Locations: []types.Location{{StartLine: 91, EndLine: 119}}},
		{ID: "http-errors@1.6.3", Name: "http-errors", Version: "1.6.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/http-errors/-/http-errors-1.6.3.tgz"}}, Locations: []types.Location{{StartLine: 120, EndLine: 130}}},
		{ID: "iconv-lite@0.4.23", Name: "iconv-lite", Version: "0.4.23", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.4.23.tgz"}}, Locations: []types.Location{{StartLine: 131, EndLine: 138}}},
		{ID: "inherits@2.0.3", Name: "inherits", Version: "2.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/inherits/-/inherits-2.0.3.tgz"}}, Locations: []types.Location{{StartLine: 139, EndLine: 143}}},
		{ID: "media-typer@0.3.0", Name: "media-typer", Version: "0.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/media-typer/-/media-typer-0.3.0.tgz"}}, Locations: []types.Location{{StartLine: 144, EndLine: 148}}},
		{ID: "mime-db@1.52.0", Name: "mime-db", Version: "1.52.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/mime-db/-/mime-db-1.52.0.tgz"}}, Locations: []types.Location{{StartLine: 149, EndLine: 153}}},
		{ID: "mime-types@2.1.35", Name: "mime-types", Version: "2.1.35", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz"}}, Locations: []types.Location{{StartLine: 154, EndLine: 161}}},
		{ID: "ms@1.0.0", Name: "ms", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-1.0.0.tgz"}}, Locations: []types.Location{{StartLine: 162, EndLine: 166}}},
		{ID: "ms@2.0.0", Name: "ms", Version: "2.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"}}, Locations: []types.Location{{StartLine: 37, EndLine: 41}, {StartLine: 113, EndLine: 117}}},
		{ID: "on-finished@2.3.0", Name: "on-finished", Version: "2.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/on-finished/-/on-finished-2.3.0.tgz"}}, Locations: []types.Location{{StartLine: 167, EndLine: 174}}},
		{ID: "parseurl@1.3.3", Name: "parseurl", Version: "1.3.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/parseurl/-/parseurl-1.3.3.tgz"}}, Locations: []types.Location{{StartLine: 175, EndLine: 179}}},
		{ID: "qs@6.5.2", Name: "qs", Version: "6.5.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz"}}, Locations: []types.Location{{StartLine: 180, EndLine: 184}}},
		{ID: "raw-body@2.3.3", Name: "raw-body", Version: "2.3.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/raw-body/-/raw-body-2.3.3.tgz"}}, Locations: []types.Location{{StartLine: 185, EndLine: 195}}},
		{ID: "safer-buffer@2.1.2", Name: "safer-buffer", Version: "2.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/safer-buffer/-/safer-buffer-2.1.2.tgz"}}, Locations: []types.Location{{StartLine: 196, EndLine: 200}}},
		{ID: "setprototypeof@1.1.0", Name: "setprototypeof", Version: "1.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/setprototypeof/-/setprototypeof-1.1.0.tgz"}}, Locations: []types.Location{{StartLine: 201, EndLine: 205}}},
		{ID: "statuses@1.4.0", Name: "statuses", Version: "1.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/statuses/-/statuses-1.4.0.tgz"}}, Locations: []types.Location{{StartLine: 206, EndLine: 210}}},
		{ID: "type-is@1.6.18", Name: "type-is", Version: "1.6.18", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/type-is/-/type-is-1.6.18.tgz"}}, Locations: []types.Location{{StartLine: 211, EndLine: 219}}},
		{ID: "unpipe@1.0.0", Name: "unpipe", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/unpipe/-/unpipe-1.0.0.tgz"}}, Locations: []types.Location{{StartLine: 220, EndLine: 224}}},
	}

	// dependencies are filled manually
	npmDeps = []types.Dependency{
		{ID: "body-parser@1.18.3", DependsOn: []string{"bytes@3.0.0", "content-type@1.0.5", "debug@2.6.9", "depd@1.1.2", "http-errors@1.6.3", "iconv-lite@0.4.23", "on-finished@2.3.0", "qs@6.5.2", "raw-body@2.3.3", "type-is@1.6.18"}},
		{ID: "debug@2.6.9", DependsOn: []string{"ms@2.0.0"}},
		{ID: "finalhandler@1.1.1", DependsOn: []string{"debug@2.6.9", "encodeurl@1.0.2", "escape-html@1.0.3", "on-finished@2.3.0", "parseurl@1.3.3", "statuses@1.4.0", "unpipe@1.0.0"}},
		{ID: "http-errors@1.6.3", DependsOn: []string{"depd@1.1.2", "inherits@2.0.3", "setprototypeof@1.1.0", "statuses@1.4.0"}},
		{ID: "iconv-lite@0.4.23", DependsOn: []string{"safer-buffer@2.1.2"}},
		{ID: "mime-types@2.1.35", DependsOn: []string{"mime-db@1.52.0"}},
		{ID: "on-finished@2.3.0", DependsOn: []string{"ee-first@1.1.1"}},
		{ID: "raw-body@2.3.3", DependsOn: []string{"bytes@3.0.0", "http-errors@1.6.3", "iconv-lite@0.4.23", "unpipe@1.0.0"}},
		{ID: "type-is@1.6.18", DependsOn: []string{"media-typer@0.3.0", "mime-types@2.1.35"}},
	}

	// ... and
	// npm i --lockfile-version 2
	// same as npmV1Libs but change `Indirect` field to false for `body-parser@1.18.3`, `finalhandler@1.1.1`, `@babel/helper-string-parser@7.19.4` and `ms@1.0.0`  libraries.
	// also need to get locations from `packages` struct
	// --- lockfile version 3 ---
	// npm i --lockfile-version 3
	// same as npmV2Libs.
	npmV2Libs = []types.Library{
		{ID: "@babel/helper-string-parser@7.19.4", Name: "@babel/helper-string-parser", Version: "7.19.4", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/@babel/helper-string-parser/-/helper-string-parser-7.19.4.tgz"}}, Locations: []types.Location{{StartLine: 21, EndLine: 28}}},
		{ID: "body-parser@1.18.3", Name: "body-parser", Version: "1.18.3", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/body-parser/-/body-parser-1.18.3.tgz"}}, Locations: []types.Location{{StartLine: 29, EndLine: 48}}},
		{ID: "bytes@3.0.0", Name: "bytes", Version: "3.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/bytes/-/bytes-3.0.0.tgz"}}, Locations: []types.Location{{StartLine: 62, EndLine: 69}}},
		{ID: "content-type@1.0.5", Name: "content-type", Version: "1.0.5", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/content-type/-/content-type-1.0.5.tgz"}}, Locations: []types.Location{{StartLine: 70, EndLine: 77}}},
		{ID: "debug@2.6.9", Name: "debug", Version: "2.6.9", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/debug/-/debug-2.6.9.tgz"}}, Locations: []types.Location{{StartLine: 49, EndLine: 56}, {StartLine: 136, EndLine: 143}}},
		{ID: "depd@1.1.2", Name: "depd", Version: "1.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/depd/-/depd-1.1.2.tgz"}}, Locations: []types.Location{{StartLine: 93, EndLine: 100}}},
		{ID: "ee-first@1.1.1", Name: "ee-first", Version: "1.1.1", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ee-first/-/ee-first-1.1.1.tgz"}}, Locations: []types.Location{{StartLine: 101, EndLine: 105}}},
		{ID: "encodeurl@1.0.2", Name: "encodeurl", Version: "1.0.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/encodeurl/-/encodeurl-1.0.2.tgz"}}, Locations: []types.Location{{StartLine: 106, EndLine: 113}}},
		{ID: "escape-html@1.0.3", Name: "escape-html", Version: "1.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/escape-html/-/escape-html-1.0.3.tgz"}}, Locations: []types.Location{{StartLine: 114, EndLine: 118}}},
		{ID: "finalhandler@1.1.1", Name: "finalhandler", Version: "1.1.1", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/finalhandler/-/finalhandler-1.1.1.tgz"}}, Locations: []types.Location{{StartLine: 119, EndLine: 135}}},
		{ID: "http-errors@1.6.3", Name: "http-errors", Version: "1.6.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/http-errors/-/http-errors-1.6.3.tgz"}}, Locations: []types.Location{{StartLine: 149, EndLine: 162}}},
		{ID: "iconv-lite@0.4.23", Name: "iconv-lite", Version: "0.4.23", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.4.23.tgz"}}, Locations: []types.Location{{StartLine: 163, EndLine: 173}}},
		{ID: "inherits@2.0.3", Name: "inherits", Version: "2.0.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/inherits/-/inherits-2.0.3.tgz"}}, Locations: []types.Location{{StartLine: 174, EndLine: 178}}},
		{ID: "media-typer@0.3.0", Name: "media-typer", Version: "0.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/media-typer/-/media-typer-0.3.0.tgz"}}, Locations: []types.Location{{StartLine: 179, EndLine: 186}}},
		{ID: "mime-db@1.52.0", Name: "mime-db", Version: "1.52.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/mime-db/-/mime-db-1.52.0.tgz"}}, Locations: []types.Location{{StartLine: 187, EndLine: 194}}},
		{ID: "mime-types@2.1.35", Name: "mime-types", Version: "2.1.35", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/mime-types/-/mime-types-2.1.35.tgz"}}, Locations: []types.Location{{StartLine: 195, EndLine: 205}}},
		{ID: "ms@1.0.0", Name: "ms", Version: "1.0.0", Indirect: false, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-1.0.0.tgz"}}, Locations: []types.Location{{StartLine: 206, EndLine: 210}}},
		{ID: "ms@2.0.0", Name: "ms", Version: "2.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"}}, Locations: []types.Location{{StartLine: 57, EndLine: 61}, {StartLine: 144, EndLine: 148}}},
		{ID: "on-finished@2.3.0", Name: "on-finished", Version: "2.3.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/on-finished/-/on-finished-2.3.0.tgz"}}, Locations: []types.Location{{StartLine: 211, EndLine: 221}}},
		{ID: "parseurl@1.3.3", Name: "parseurl", Version: "1.3.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/parseurl/-/parseurl-1.3.3.tgz"}}, Locations: []types.Location{{StartLine: 222, EndLine: 229}}},
		{ID: "qs@6.5.2", Name: "qs", Version: "6.5.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz"}}, Locations: []types.Location{{StartLine: 230, EndLine: 237}}},
		{ID: "raw-body@2.3.3", Name: "raw-body", Version: "2.3.3", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/raw-body/-/raw-body-2.3.3.tgz"}}, Locations: []types.Location{{StartLine: 238, EndLine: 251}}},
		{ID: "safer-buffer@2.1.2", Name: "safer-buffer", Version: "2.1.2", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/safer-buffer/-/safer-buffer-2.1.2.tgz"}}, Locations: []types.Location{{StartLine: 252, EndLine: 256}}},
		{ID: "setprototypeof@1.1.0", Name: "setprototypeof", Version: "1.1.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/setprototypeof/-/setprototypeof-1.1.0.tgz"}}, Locations: []types.Location{{StartLine: 257, EndLine: 261}}},
		{ID: "statuses@1.4.0", Name: "statuses", Version: "1.4.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/statuses/-/statuses-1.4.0.tgz"}}, Locations: []types.Location{{StartLine: 262, EndLine: 269}}},
		{ID: "type-is@1.6.18", Name: "type-is", Version: "1.6.18", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/type-is/-/type-is-1.6.18.tgz"}}, Locations: []types.Location{{StartLine: 270, EndLine: 281}}},
		{ID: "unpipe@1.0.0", Name: "unpipe", Version: "1.0.0", Indirect: true, ExternalReferences: []types.ExternalRef{{Type: types.RefOther, URL: "https://registry.npmjs.org/unpipe/-/unpipe-1.0.0.tgz"}}, Locations: []types.Location{{StartLine: 282, EndLine: 289}}},
	}
)
