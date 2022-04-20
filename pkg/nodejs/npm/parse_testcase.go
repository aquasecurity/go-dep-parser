package npm

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save promise jquery
	// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmNormal = []types.Library{
		{"asap", "2.0.7", ""},
		{"jquery", "3.4.0", ""},
		{"promise", "8.0.3", ""},
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
		{"asap", "2.0.6", ""},
		{"jquery", "3.4.0", ""},
		{"js-tokens", "4.0.0", ""},
		{"loose-envify", "1.4.0", ""},
		{"object-assign", "4.1.1", ""},
		{"promise", "8.0.3", ""},
		{"prop-types", "15.7.2", ""},
		{"react", "16.8.6", ""},
		{"react-is", "16.8.6", ""},
		{"redux", "4.0.1", ""},
		{"scheduler", "0.13.6", ""},
		{"symbol-observable", "1.2.0", ""},
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
		{"asap", "2.0.6", ""},
		{"jquery", "3.4.0", ""},
		{"js-tokens", "4.0.0", ""},
		{"loose-envify", "1.4.0", ""},
		{"object-assign", "4.1.1", ""},
		{"promise", "8.0.3", ""},
		{"prop-types", "15.7.2", ""},
		{"react", "16.8.6", ""},
		{"react-is", "16.8.6", ""},
		{"redux", "4.0.1", ""},
		{"scheduler", "0.13.6", ""},
		{"symbol-observable", "1.2.0", ""},
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
		{"accepts", "1.3.6", ""},
		{"ajv", "6.10.0", ""},
		{"ansi-styles", "3.2.1", ""},
		{"array-flatten", "1.1.1", ""},
		{"asap", "2.0.6", ""},
		{"asn1", "0.2.4", ""},
		{"assert-plus", "1.0.0", ""},
		{"async", "2.6.2", ""},
		{"asynckit", "0.4.0", ""},
		{"aws-sign2", "0.7.0", ""},
		{"aws4", "1.8.0", ""},
		{"axios", "0.18.0", ""},
		{"bcrypt-pbkdf", "1.0.2", ""},
		{"body-parser", "1.18.3", ""},
		{"bytes", "3.0.0", ""},
		{"caseless", "0.12.0", ""},
		{"chalk", "2.4.2", ""},
		{"color-convert", "1.9.3", ""},
		{"color-name", "1.1.3", ""},
		{"combined-stream", "1.0.7", ""},
		{"commander", "2.20.0", ""},
		{"content-disposition", "0.5.2", ""},
		{"content-type", "1.0.4", ""},
		{"cookie-signature", "1.0.6", ""},
		{"cookie", "0.3.1", ""},
		{"core-util-is", "1.0.2", ""},
		{"dashdash", "1.14.1", ""},
		{"debug", "2.6.9", ""},
		{"debug", "3.2.6", ""},
		{"delayed-stream", "1.0.0", ""},
		{"depd", "1.1.2", ""},
		{"destroy", "1.0.4", ""},
		{"ecc-jsbn", "0.1.2", ""},
		{"ee-first", "1.1.1", ""},
		{"encodeurl", "1.0.2", ""},
		{"escape-html", "1.0.3", ""},
		{"escape-string-regexp", "1.0.5", ""},
		{"etag", "1.8.1", ""},
		{"express", "4.16.4", ""},
		{"extend", "3.0.2", ""},
		{"extsprintf", "1.3.0", ""},
		{"fast-deep-equal", "2.0.1", ""},
		{"fast-json-stable-stringify", "2.0.0", ""},
		{"finalhandler", "1.1.1", ""},
		{"follow-redirects", "1.7.0", ""},
		{"forever-agent", "0.6.1", ""},
		{"form-data", "2.3.3", ""},
		{"forwarded", "0.1.2", ""},
		{"fresh", "0.5.2", ""},
		{"getpass", "0.1.7", ""},
		{"har-schema", "2.0.0", ""},
		{"har-validator", "5.1.3", ""},
		{"has-flag", "3.0.0", ""},
		{"http-errors", "1.6.3", ""},
		{"http-signature", "1.2.0", ""},
		{"iconv-lite", "0.4.23", ""},
		{"inherits", "2.0.3", ""},
		{"ipaddr.js", "1.9.0", ""},
		{"is-buffer", "1.1.6", ""},
		{"is-typedarray", "1.0.0", ""},
		{"isstream", "0.1.2", ""},
		{"jquery", "3.4.0", ""},
		{"js-tokens", "4.0.0", ""},
		{"jsbn", "0.1.1", ""},
		{"json-schema-traverse", "0.4.1", ""},
		{"json-schema", "0.2.3", ""},
		{"json-stringify-safe", "5.0.1", ""},
		{"jsprim", "1.4.1", ""},
		{"lodash", "4.17.11", ""},
		{"loose-envify", "1.4.0", ""},
		{"media-typer", "0.3.0", ""},
		{"merge-descriptors", "1.0.1", ""},
		{"methods", "1.1.2", ""},
		{"mime-db", "1.40.0", ""},
		{"mime-types", "2.1.24", ""},
		{"mime", "1.4.1", ""},
		{"ms", "2.0.0", ""},
		{"ms", "2.1.1", ""},
		{"negotiator", "0.6.1", ""},
		{"oauth-sign", "0.9.0", ""},
		{"object-assign", "4.1.1", ""},
		{"on-finished", "2.3.0", ""},
		{"parseurl", "1.3.3", ""},
		{"path-to-regexp", "0.1.7", ""},
		{"performance-now", "2.1.0", ""},
		{"promise", "8.0.3", ""},
		{"prop-types", "15.7.2", ""},
		{"proxy-addr", "2.0.5", ""},
		{"psl", "1.1.31", ""},
		{"punycode", "1.4.1", ""},
		{"punycode", "2.1.1", ""},
		{"qs", "6.5.2", ""},
		{"range-parser", "1.2.0", ""},
		{"raw-body", "2.3.3", ""},
		{"react-is", "16.8.6", ""},
		{"react", "16.8.6", ""},
		{"redux", "4.0.1", ""},
		{"request", "2.88.0", ""},
		{"safe-buffer", "5.1.2", ""},
		{"safer-buffer", "2.1.2", ""},
		{"scheduler", "0.13.6", ""},
		{"send", "0.16.2", ""},
		{"serve-static", "1.13.2", ""},
		{"setprototypeof", "1.1.0", ""},
		{"sshpk", "1.16.1", ""},
		{"statuses", "1.4.0", ""},
		{"supports-color", "5.5.0", ""},
		{"symbol-observable", "1.2.0", ""},
		{"tough-cookie", "2.4.3", ""},
		{"tunnel-agent", "0.6.0", ""},
		{"tweetnacl", "0.14.5", ""},
		{"type-is", "1.6.18", ""},
		{"unpipe", "1.0.0", ""},
		{"uri-js", "4.2.2", ""},
		{"utils-merge", "1.0.1", ""},
		{"uuid", "3.3.2", ""},
		{"vary", "1.1.2", ""},
		{"verror", "1.10.0", ""},
		{"vue", "2.6.10", ""},
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
		{"debug", "2.0.0", ""},
		{"debug", "2.6.9", ""},
		{"ms", "0.6.2", ""},
		{"ms", "2.0.0", ""},
		{"ms", "2.1.0", ""},
		{"ms", "2.1.1", ""},
		{"depd", "1.1.2", ""},
		{"destroy", "1.0.4", ""},
		{"ee-first", "1.1.1", ""},
		{"encodeurl", "1.0.2", ""},
		{"escape-html", "1.0.3", ""},
		{"etag", "1.8.1", ""},
		{"fresh", "0.5.2", ""},
		{"http-errors", "1.7.3", ""},
		{"inherits", "2.0.4", ""},
		{"mime", "1.6.0", ""},
		{"on-finished", "2.3.0", ""},
		{"range-parser", "1.2.1", ""},
		{"send", "0.17.1", ""},
		{"setprototypeof", "1.1.1", ""},
		{"statuses", "1.5.0", ""},
		{"toidentifier", "1.0.0", ""},
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
