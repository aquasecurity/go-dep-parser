package npm

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save promise jquery
	// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmNormal = []types.Library{
		{Name: "asap", Version: "2.0.7"},
		{Name: "jquery", Version: "3.4.0"},
		{Name: "promise", Version: "8.0.3"},
	}

	npmNormalDeps = []types.Dependency{
		{
			ID:        "promise@8.0.3",
			DependsOn: []string{"asap@2.0.7"},
		},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmReact = []types.Library{
		{Name: "asap", Version: "2.0.6"},
		{Name: "jquery", Version: "3.4.0"},
		{Name: "js-tokens", Version: "4.0.0"},
		{Name: "loose-envify", Version: "1.4.0"},
		{Name: "object-assign", Version: "4.1.1"},
		{Name: "promise", Version: "8.0.3"},
		{Name: "prop-types", Version: "15.7.2"},
		{Name: "react", Version: "16.8.6"},
		{Name: "react-is", Version: "16.8.6"},
		{Name: "redux", Version: "4.0.1"},
		{Name: "scheduler", Version: "0.13.6"},
		{Name: "symbol-observable", Version: "1.2.0"},
	}
	npmReactDeps = []types.Dependency{
		{
			ID:        "loose-envify@1.4.0",
			DependsOn: []string{"js-tokens@4.0.0"},
		},
		{
			ID:        "promise@8.0.3",
			DependsOn: []string{"asap@2.0.6"},
		},
		{
			ID:        "prop-types@15.7.2",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1", "react-is@16.8.6"},
		},
		{
			ID:        "react@16.8.6",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1", "prop-types@15.7.2", "scheduler@0.13.6"},
		},
		{
			ID:        "redux@4.0.1",
			DependsOn: []string{"loose-envify@1.4.0", "symbol-observable@1.2.0"},
		},
		{
			ID:        "scheduler@0.13.6",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1"},
		},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm install --save-dev mocha
	// npm ls -prod | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmWithDev = []types.Library{
		{Name: "asap", Version: "2.0.6"},
		{Name: "jquery", Version: "3.4.0"},
		{Name: "js-tokens", Version: "4.0.0"},
		{Name: "loose-envify", Version: "1.4.0"},
		{Name: "object-assign", Version: "4.1.1"},
		{Name: "promise", Version: "8.0.3"},
		{Name: "prop-types", Version: "15.7.2"},
		{Name: "react", Version: "16.8.6"},
		{Name: "react-is", Version: "16.8.6"},
		{Name: "redux", Version: "4.0.1"},
		{Name: "scheduler", Version: "0.13.6"},
		{Name: "symbol-observable", Version: "1.2.0"},
	}
	npmWithDevDeps = []types.Dependency{
		{
			ID:        "loose-envify@1.4.0",
			DependsOn: []string{"js-tokens@4.0.0"},
		},
		{
			ID:        "promise@8.0.3",
			DependsOn: []string{"asap@2.0.6"},
		},
		{
			ID:        "prop-types@15.7.2",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1", "react-is@16.8.6"},
		},
		{
			ID:        "react@16.8.6",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1", "prop-types@15.7.2", "scheduler@0.13.6"},
		},
		{
			ID:        "redux@4.0.1",
			DependsOn: []string{"loose-envify@1.4.0", "symbol-observable@1.2.0"},
		},
		{
			ID:        "scheduler@0.13.6",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1"},
		},
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm install --save-dev mocha
	// npm install --save lodash request chalk commander express async axios vue
	// npm ls -prod | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmMany = []types.Library{
		{Name: "accepts", Version: "1.3.6"},
		{Name: "ajv", Version: "6.10.0"},
		{Name: "ansi-styles", Version: "3.2.1"},
		{Name: "array-flatten", Version: "1.1.1"},
		{Name: "asap", Version: "2.0.6"},
		{Name: "asn1", Version: "0.2.4"},
		{Name: "assert-plus", Version: "1.0.0"},
		{Name: "async", Version: "2.6.2"},
		{Name: "asynckit", Version: "0.4.0"},
		{Name: "aws-sign2", Version: "0.7.0"},
		{Name: "aws4", Version: "1.8.0"},
		{Name: "axios", Version: "0.18.0"},
		{Name: "bcrypt-pbkdf", Version: "1.0.2"},
		{Name: "body-parser", Version: "1.18.3"},
		{Name: "bytes", Version: "3.0.0"},
		{Name: "caseless", Version: "0.12.0"},
		{Name: "chalk", Version: "2.4.2"},
		{Name: "color-convert", Version: "1.9.3"},
		{Name: "color-name", Version: "1.1.3"},
		{Name: "combined-stream", Version: "1.0.7"},
		{Name: "commander", Version: "2.20.0"},
		{Name: "content-disposition", Version: "0.5.2"},
		{Name: "content-type", Version: "1.0.4"},
		{Name: "cookie-signature", Version: "1.0.6"},
		{Name: "cookie", Version: "0.3.1"},
		{Name: "core-util-is", Version: "1.0.2"},
		{Name: "dashdash", Version: "1.14.1"},
		{Name: "debug", Version: "2.6.9"},
		{Name: "debug", Version: "3.2.6"},
		{Name: "delayed-stream", Version: "1.0.0"},
		{Name: "depd", Version: "1.1.2"},
		{Name: "destroy", Version: "1.0.4"},
		{Name: "ecc-jsbn", Version: "0.1.2"},
		{Name: "ee-first", Version: "1.1.1"},
		{Name: "encodeurl", Version: "1.0.2"},
		{Name: "escape-html", Version: "1.0.3"},
		{Name: "escape-string-regexp", Version: "1.0.5"},
		{Name: "etag", Version: "1.8.1"},
		{Name: "express", Version: "4.16.4"},
		{Name: "extend", Version: "3.0.2"},
		{Name: "extsprintf", Version: "1.3.0"},
		{Name: "fast-deep-equal", Version: "2.0.1"},
		{Name: "fast-json-stable-stringify", Version: "2.0.0"},
		{Name: "finalhandler", Version: "1.1.1"},
		{Name: "follow-redirects", Version: "1.7.0"},
		{Name: "forever-agent", Version: "0.6.1"},
		{Name: "form-data", Version: "2.3.3"},
		{Name: "forwarded", Version: "0.1.2"},
		{Name: "fresh", Version: "0.5.2"},
		{Name: "getpass", Version: "0.1.7"},
		{Name: "har-schema", Version: "2.0.0"},
		{Name: "har-validator", Version: "5.1.3"},
		{Name: "has-flag", Version: "3.0.0"},
		{Name: "http-errors", Version: "1.6.3"},
		{Name: "http-signature", Version: "1.2.0"},
		{Name: "iconv-lite", Version: "0.4.23"},
		{Name: "inherits", Version: "2.0.3"},
		{Name: "ipaddr.js", Version: "1.9.0"},
		{Name: "is-buffer", Version: "1.1.6"},
		{Name: "is-typedarray", Version: "1.0.0"},
		{Name: "isstream", Version: "0.1.2"},
		{Name: "jquery", Version: "3.4.0"},
		{Name: "js-tokens", Version: "4.0.0"},
		{Name: "jsbn", Version: "0.1.1"},
		{Name: "json-schema-traverse", Version: "0.4.1"},
		{Name: "json-schema", Version: "0.2.3"},
		{Name: "json-stringify-safe", Version: "5.0.1"},
		{Name: "jsprim", Version: "1.4.1"},
		{Name: "lodash", Version: "4.17.11"},
		{Name: "loose-envify", Version: "1.4.0"},
		{Name: "media-typer", Version: "0.3.0"},
		{Name: "merge-descriptors", Version: "1.0.1"},
		{Name: "methods", Version: "1.1.2"},
		{Name: "mime-db", Version: "1.40.0"},
		{Name: "mime-types", Version: "2.1.24"},
		{Name: "mime", Version: "1.4.1"},
		{Name: "ms", Version: "2.0.0"},
		{Name: "ms", Version: "2.1.1"},
		{Name: "negotiator", Version: "0.6.1"},
		{Name: "oauth-sign", Version: "0.9.0"},
		{Name: "object-assign", Version: "4.1.1"},
		{Name: "on-finished", Version: "2.3.0"},
		{Name: "parseurl", Version: "1.3.3"},
		{Name: "path-to-regexp", Version: "0.1.7"},
		{Name: "performance-now", Version: "2.1.0"},
		{Name: "promise", Version: "8.0.3"},
		{Name: "prop-types", Version: "15.7.2"},
		{Name: "proxy-addr", Version: "2.0.5"},
		{Name: "psl", Version: "1.1.31"},
		{Name: "punycode", Version: "1.4.1"},
		{Name: "punycode", Version: "2.1.1"},
		{Name: "qs", Version: "6.5.2"},
		{Name: "range-parser", Version: "1.2.0"},
		{Name: "raw-body", Version: "2.3.3"},
		{Name: "react-is", Version: "16.8.6"},
		{Name: "react", Version: "16.8.6"},
		{Name: "redux", Version: "4.0.1"},
		{Name: "request", Version: "2.88.0"},
		{Name: "safe-buffer", Version: "5.1.2"},
		{Name: "safer-buffer", Version: "2.1.2"},
		{Name: "scheduler", Version: "0.13.6"},
		{Name: "send", Version: "0.16.2"},
		{Name: "serve-static", Version: "1.13.2"},
		{Name: "setprototypeof", Version: "1.1.0"},
		{Name: "sshpk", Version: "1.16.1"},
		{Name: "statuses", Version: "1.4.0"},
		{Name: "supports-color", Version: "5.5.0"},
		{Name: "symbol-observable", Version: "1.2.0"},
		{Name: "tough-cookie", Version: "2.4.3"},
		{Name: "tunnel-agent", Version: "0.6.0"},
		{Name: "tweetnacl", Version: "0.14.5"},
		{Name: "type-is", Version: "1.6.18"},
		{Name: "unpipe", Version: "1.0.0"},
		{Name: "uri-js", Version: "4.2.2"},
		{Name: "utils-merge", Version: "1.0.1"},
		{Name: "uuid", Version: "3.3.2"},
		{Name: "vary", Version: "1.1.2"},
		{Name: "verror", Version: "1.10.0"},
		{Name: "vue", Version: "2.6.10"},
	}
	npmManyDeps = []types.Dependency{
		{
			ID:        "accepts@1.3.6",
			DependsOn: []string{"mime-types@2.1.24", "negotiator@0.6.1"},
		},
		{
			ID:        "ajv@6.10.0",
			DependsOn: []string{"fast-deep-equal@2.0.1", "fast-json-stable-stringify@2.0.0", "json-schema-traverse@0.4.1", "uri-js@4.2.2"},
		},
		{
			ID:        "ansi-styles@3.2.1",
			DependsOn: []string{"color-convert@1.9.3"},
		},
		{
			ID:        "asn1@0.2.4",
			DependsOn: []string{"safer-buffer@2.1.2"},
		},
		{
			ID:        "async@2.6.2",
			DependsOn: []string{"lodash@4.17.11"},
		},
		{
			ID:        "axios@0.18.0",
			DependsOn: []string{"follow-redirects@1.7.0", "is-buffer@1.1.6"},
		},
		{
			ID:        "bcrypt-pbkdf@1.0.2",
			DependsOn: []string{"tweetnacl@0.14.5"},
		},
		{
			ID:        "body-parser@1.18.3",
			DependsOn: []string{"bytes@3.0.0", "content-type@1.0.4", "debug@2.6.9", "depd@1.1.2", "http-errors@1.6.3", "iconv-lite@0.4.23", "on-finished@2.3.0", "qs@6.5.2", "raw-body@2.3.3", "type-is@1.6.18"},
		},
		{
			ID:        "chalk@2.4.2",
			DependsOn: []string{"ansi-styles@3.2.1", "escape-string-regexp@1.0.5", "supports-color@5.5.0"},
		},
		{
			ID:        "color-convert@1.9.3",
			DependsOn: []string{"color-name@1.1.3"},
		},
		{
			ID:        "combined-stream@1.0.7",
			DependsOn: []string{"delayed-stream@1.0.0"},
		},
		{
			ID:        "dashdash@1.14.1",
			DependsOn: []string{"assert-plus@1.0.0"},
		},
		{
			ID:        "debug@3.2.6",
			DependsOn: []string{"ms@2.1.1"},
		},
		{
			ID:        "ecc-jsbn@0.1.2",
			DependsOn: []string{"jsbn@0.1.1", "safer-buffer@2.1.2"},
		},
		{
			ID:        "express@4.16.4",
			DependsOn: []string{"accepts@1.3.6", "array-flatten@1.1.1", "body-parser@1.18.3", "content-disposition@0.5.2", "content-type@1.0.4", "cookie-signature@1.0.6", "cookie@0.3.1", "debug@2.6.9", "depd@1.1.2", "encodeurl@1.0.2", "escape-html@1.0.3", "etag@1.8.1", "finalhandler@1.1.1", "fresh@0.5.2", "merge-descriptors@1.0.1", "methods@1.1.2", "on-finished@2.3.0", "parseurl@1.3.3", "path-to-regexp@0.1.7", "proxy-addr@2.0.5", "qs@6.5.2", "range-parser@1.2.0", "safe-buffer@5.1.2", "send@0.16.2", "serve-static@1.13.2", "setprototypeof@1.1.0", "statuses@1.4.0", "type-is@1.6.18", "utils-merge@1.0.1", "vary@1.1.2"},
		},
		{
			ID:        "finalhandler@1.1.1",
			DependsOn: []string{"debug@2.6.9", "encodeurl@1.0.2", "escape-html@1.0.3", "on-finished@2.3.0", "parseurl@1.3.3", "statuses@1.4.0", "unpipe@1.0.0"},
		},
		{
			ID:        "follow-redirects@1.7.0",
			DependsOn: []string{"debug@3.2.6"},
		},
		{
			ID:        "form-data@2.3.3",
			DependsOn: []string{"asynckit@0.4.0", "combined-stream@1.0.7", "mime-types@2.1.24"},
		},
		{
			ID:        "getpass@0.1.7",
			DependsOn: []string{"assert-plus@1.0.0"},
		},
		{
			ID:        "har-validator@5.1.3",
			DependsOn: []string{"ajv@6.10.0", "har-schema@2.0.0"},
		},
		{
			ID:        "http-errors@1.6.3",
			DependsOn: []string{"depd@1.1.2", "inherits@2.0.3", "setprototypeof@1.1.0", "statuses@1.4.0"},
		},
		{
			ID:        "http-signature@1.2.0",
			DependsOn: []string{"assert-plus@1.0.0", "jsprim@1.4.1", "sshpk@1.16.1"},
		},
		{
			ID:        "iconv-lite@0.4.23",
			DependsOn: []string{"safer-buffer@2.1.2"},
		},
		{
			ID:        "jsprim@1.4.1",
			DependsOn: []string{"assert-plus@1.0.0", "extsprintf@1.3.0", "json-schema@0.2.3", "verror@1.10.0"},
		},
		{
			ID:        "loose-envify@1.4.0",
			DependsOn: []string{"js-tokens@4.0.0"},
		},
		{
			ID:        "mime-types@2.1.24",
			DependsOn: []string{"mime-db@1.40.0"},
		},
		{
			ID:        "on-finished@2.3.0",
			DependsOn: []string{"ee-first@1.1.1"},
		},
		{
			ID:        "promise@8.0.3",
			DependsOn: []string{"asap@2.0.6"},
		},
		{
			ID:        "prop-types@15.7.2",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1", "react-is@16.8.6"},
		},
		{
			ID:        "proxy-addr@2.0.5",
			DependsOn: []string{"forwarded@0.1.2", "ipaddr.js@1.9.0"},
		},
		{
			ID:        "raw-body@2.3.3",
			DependsOn: []string{"bytes@3.0.0", "http-errors@1.6.3", "iconv-lite@0.4.23", "unpipe@1.0.0"},
		},
		{
			ID:        "react@16.8.6",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1", "prop-types@15.7.2", "scheduler@0.13.6"},
		},
		{
			ID:        "redux@4.0.1",
			DependsOn: []string{"loose-envify@1.4.0", "symbol-observable@1.2.0"},
		},
		{
			ID:        "request@2.88.0",
			DependsOn: []string{"aws-sign2@0.7.0", "aws4@1.8.0", "caseless@0.12.0", "combined-stream@1.0.7", "extend@3.0.2", "forever-agent@0.6.1", "form-data@2.3.3", "har-validator@5.1.3", "http-signature@1.2.0", "is-typedarray@1.0.0", "isstream@0.1.2", "json-stringify-safe@5.0.1", "mime-types@2.1.24", "oauth-sign@0.9.0", "performance-now@2.1.0", "qs@6.5.2", "safe-buffer@5.1.2", "tough-cookie@2.4.3", "tunnel-agent@0.6.0", "uuid@3.3.2"},
		},
		{
			ID:        "scheduler@0.13.6",
			DependsOn: []string{"loose-envify@1.4.0", "object-assign@4.1.1"},
		},
		{
			ID:        "send@0.16.2",
			DependsOn: []string{"debug@2.6.9", "depd@1.1.2", "destroy@1.0.4", "encodeurl@1.0.2", "escape-html@1.0.3", "etag@1.8.1", "fresh@0.5.2", "http-errors@1.6.3", "mime@1.4.1", "ms@2.0.0", "on-finished@2.3.0", "range-parser@1.2.0", "statuses@1.4.0"},
		},
		{
			ID:        "serve-static@1.13.2",
			DependsOn: []string{"encodeurl@1.0.2", "escape-html@1.0.3", "parseurl@1.3.3", "send@0.16.2"},
		},
		{
			ID:        "sshpk@1.16.1",
			DependsOn: []string{"asn1@0.2.4", "assert-plus@1.0.0", "bcrypt-pbkdf@1.0.2", "dashdash@1.14.1", "ecc-jsbn@0.1.2", "getpass@0.1.7", "jsbn@0.1.1", "safer-buffer@2.1.2", "tweetnacl@0.14.5"},
		},
		{
			ID:        "tough-cookie@2.4.3",
			DependsOn: []string{"psl@1.1.31", "punycode@1.4.1"},
		},
		{
			ID:        "tunnel-agent@0.6.0",
			DependsOn: []string{"safe-buffer@5.1.2"},
		},
		{
			ID:        "type-is@1.6.18",
			DependsOn: []string{"media-typer@0.3.0", "mime-types@2.1.24"},
		},
		{
			ID:        "uri-js@4.2.2",
			DependsOn: []string{"punycode@2.1.1"},
		},
		{
			ID:        "verror@1.10.0",
			DependsOn: []string{"assert-plus@1.0.0", "core-util-is@1.0.2", "extsprintf@1.3.0"},
		},
	}

	// manually created
	npmNested = []types.Library{
		{Name: "debug", Version: "2.0.0"},
		{Name: "debug", Version: "2.6.9"},
		{Name: "ms", Version: "0.6.2"},
		{Name: "ms", Version: "2.0.0"},
		{Name: "ms", Version: "2.1.0"},
		{Name: "ms", Version: "2.1.1"},
		{Name: "send", Version: "0.17.1"},
		{Name: "depd", Version: "1.1.2"},
		{Name: "destroy", Version: "1.0.4"},
		{Name: "ee-first", Version: "1.1.1"},
		{Name: "encodeurl", Version: "1.0.2"},
		{Name: "escape-html", Version: "1.0.3"},
		{Name: "etag", Version: "1.8.1"},
		{Name: "fresh", Version: "0.5.2"},
		{Name: "http-errors", Version: "1.7.3"},
		{Name: "inherits", Version: "2.0.4"},
		{Name: "mime", Version: "1.6.0"},
		{Name: "on-finished", Version: "2.3.0"},
		{Name: "range-parser", Version: "1.2.1"},
		{Name: "setprototypeof", Version: "1.1.1"},
		{Name: "statuses", Version: "1.5.0"},
		{Name: "toidentifier", Version: "1.0.0"},
	}
	npmNestedDeps = []types.Dependency{{
		ID:        "send@0.17.1",
		DependsOn: []string{"fresh@0.5.2", "ms@2.1.1", "on-finished@2.3.0", "statuses@1.5.0", "escape-html@1.0.3", "depd@1.1.2", "destroy@1.0.4", "encodeurl@1.0.2", "etag@1.8.1", "http-errors@1.7.3", "mime@1.6.0", "range-parser@1.2.1", "debug@2.6.9"},
	}, {
		ID:        "http-errors@1.7.3",
		DependsOn: []string{"depd@1.1.2", "inherits@2.0.4", "setprototypeof@1.1.1", "statuses@1.5.0", "toidentifier@1.0.0"},
	}, {
		ID: "on-finished@2.3.0", DependsOn: []string{"ee-first@1.1.1"},
	}, {
		ID: "debug@2.0.0", DependsOn: []string{"ms@0.6.2"},
	}}
)
