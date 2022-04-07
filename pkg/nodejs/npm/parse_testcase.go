package npm

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save promise jquery
	// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmNormal = []types.Library{
		types.NewLibrary("asap", "2.0.6", ""),
		types.NewLibrary("jquery", "3.4.0", ""),
		types.NewLibrary("promise", "8.0.3", ""),
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm ls | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmReact = []types.Library{
		types.NewLibrary("asap", "2.0.6", ""),
		types.NewLibrary("jquery", "3.4.0", ""),
		types.NewLibrary("js-tokens", "4.0.0", ""),
		types.NewLibrary("loose-envify", "1.4.0", ""),
		types.NewLibrary("object-assign", "4.1.1", ""),
		types.NewLibrary("promise", "8.0.3", ""),
		types.NewLibrary("prop-types", "15.7.2", ""),
		types.NewLibrary("react", "16.8.6", ""),
		types.NewLibrary("react-is", "16.8.6", ""),
		types.NewLibrary("redux", "4.0.1", ""),
		types.NewLibrary("scheduler", "0.13.6", ""),
		types.NewLibrary("symbol-observable", "1.2.0", ""),
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm install --save-dev mocha
	// npm ls -prod | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmWithDev = []types.Library{
		types.NewLibrary("asap", "2.0.6", ""),
		types.NewLibrary("jquery", "3.4.0", ""),
		types.NewLibrary("js-tokens", "4.0.0", ""),
		types.NewLibrary("loose-envify", "1.4.0", ""),
		types.NewLibrary("object-assign", "4.1.1", ""),
		types.NewLibrary("promise", "8.0.3", ""),
		types.NewLibrary("prop-types", "15.7.2", ""),
		types.NewLibrary("react", "16.8.6", ""),
		types.NewLibrary("react-is", "16.8.6", ""),
		types.NewLibrary("redux", "4.0.1", ""),
		types.NewLibrary("scheduler", "0.13.6", ""),
		types.NewLibrary("symbol-observable", "1.2.0", ""),
	}

	// docker run --name node --rm -it node:12-alpine sh
	// npm init --force
	// npm install --save react redux
	// npm install --save-dev mocha
	// npm install --save lodash request chalk commander express async axios vue
	// npm ls -prod | grep -E -o "\S+@\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	npmMany = []types.Library{
		types.NewLibrary("accepts", "1.3.6", ""),
		types.NewLibrary("ajv", "6.10.0", ""),
		types.NewLibrary("ansi-styles", "3.2.1", ""),
		types.NewLibrary("array-flatten", "1.1.1", ""),
		types.NewLibrary("asap", "2.0.6", ""),
		types.NewLibrary("asn1", "0.2.4", ""),
		types.NewLibrary("assert-plus", "1.0.0", ""),
		types.NewLibrary("async", "2.6.2", ""),
		types.NewLibrary("asynckit", "0.4.0", ""),
		types.NewLibrary("aws-sign2", "0.7.0", ""),
		types.NewLibrary("aws4", "1.8.0", ""),
		types.NewLibrary("axios", "0.18.0", ""),
		types.NewLibrary("bcrypt-pbkdf", "1.0.2", ""),
		types.NewLibrary("body-parser", "1.18.3", ""),
		types.NewLibrary("bytes", "3.0.0", ""),
		types.NewLibrary("caseless", "0.12.0", ""),
		types.NewLibrary("chalk", "2.4.2", ""),
		types.NewLibrary("color-convert", "1.9.3", ""),
		types.NewLibrary("color-name", "1.1.3", ""),
		types.NewLibrary("combined-stream", "1.0.7", ""),
		types.NewLibrary("commander", "2.20.0", ""),
		types.NewLibrary("content-disposition", "0.5.2", ""),
		types.NewLibrary("content-type", "1.0.4", ""),
		types.NewLibrary("cookie-signature", "1.0.6", ""),
		types.NewLibrary("cookie", "0.3.1", ""),
		types.NewLibrary("core-util-is", "1.0.2", ""),
		types.NewLibrary("dashdash", "1.14.1", ""),
		types.NewLibrary("debug", "2.6.9", ""),
		types.NewLibrary("debug", "3.2.6", ""),
		types.NewLibrary("delayed-stream", "1.0.0", ""),
		types.NewLibrary("depd", "1.1.2", ""),
		types.NewLibrary("destroy", "1.0.4", ""),
		types.NewLibrary("ecc-jsbn", "0.1.2", ""),
		types.NewLibrary("ee-first", "1.1.1", ""),
		types.NewLibrary("encodeurl", "1.0.2", ""),
		types.NewLibrary("escape-html", "1.0.3", ""),
		types.NewLibrary("escape-string-regexp", "1.0.5", ""),
		types.NewLibrary("etag", "1.8.1", ""),
		types.NewLibrary("express", "4.16.4", ""),
		types.NewLibrary("extend", "3.0.2", ""),
		types.NewLibrary("extsprintf", "1.3.0", ""),
		types.NewLibrary("fast-deep-equal", "2.0.1", ""),
		types.NewLibrary("fast-json-stable-stringify", "2.0.0", ""),
		types.NewLibrary("finalhandler", "1.1.1", ""),
		types.NewLibrary("follow-redirects", "1.7.0", ""),
		types.NewLibrary("forever-agent", "0.6.1", ""),
		types.NewLibrary("form-data", "2.3.3", ""),
		types.NewLibrary("forwarded", "0.1.2", ""),
		types.NewLibrary("fresh", "0.5.2", ""),
		types.NewLibrary("getpass", "0.1.7", ""),
		types.NewLibrary("har-schema", "2.0.0", ""),
		types.NewLibrary("har-validator", "5.1.3", ""),
		types.NewLibrary("has-flag", "3.0.0", ""),
		types.NewLibrary("http-errors", "1.6.3", ""),
		types.NewLibrary("http-signature", "1.2.0", ""),
		types.NewLibrary("iconv-lite", "0.4.23", ""),
		types.NewLibrary("inherits", "2.0.3", ""),
		types.NewLibrary("ipaddr.js", "1.9.0", ""),
		types.NewLibrary("is-buffer", "1.1.6", ""),
		types.NewLibrary("is-typedarray", "1.0.0", ""),
		types.NewLibrary("isstream", "0.1.2", ""),
		types.NewLibrary("jquery", "3.4.0", ""),
		types.NewLibrary("js-tokens", "4.0.0", ""),
		types.NewLibrary("jsbn", "0.1.1", ""),
		types.NewLibrary("json-schema-traverse", "0.4.1", ""),
		types.NewLibrary("json-schema", "0.2.3", ""),
		types.NewLibrary("json-stringify-safe", "5.0.1", ""),
		types.NewLibrary("jsprim", "1.4.1", ""),
		types.NewLibrary("lodash", "4.17.11", ""),
		types.NewLibrary("loose-envify", "1.4.0", ""),
		types.NewLibrary("media-typer", "0.3.0", ""),
		types.NewLibrary("merge-descriptors", "1.0.1", ""),
		types.NewLibrary("methods", "1.1.2", ""),
		types.NewLibrary("mime-db", "1.40.0", ""),
		types.NewLibrary("mime-types", "2.1.24", ""),
		types.NewLibrary("mime", "1.4.1", ""),
		types.NewLibrary("ms", "2.0.0", ""),
		types.NewLibrary("ms", "2.1.1", ""),
		types.NewLibrary("negotiator", "0.6.1", ""),
		types.NewLibrary("oauth-sign", "0.9.0", ""),
		types.NewLibrary("object-assign", "4.1.1", ""),
		types.NewLibrary("on-finished", "2.3.0", ""),
		types.NewLibrary("parseurl", "1.3.3", ""),
		types.NewLibrary("path-to-regexp", "0.1.7", ""),
		types.NewLibrary("performance-now", "2.1.0", ""),
		types.NewLibrary("promise", "8.0.3", ""),
		types.NewLibrary("prop-types", "15.7.2", ""),
		types.NewLibrary("proxy-addr", "2.0.5", ""),
		types.NewLibrary("psl", "1.1.31", ""),
		types.NewLibrary("punycode", "1.4.1", ""),
		types.NewLibrary("punycode", "2.1.1", ""),
		types.NewLibrary("qs", "6.5.2", ""),
		types.NewLibrary("range-parser", "1.2.0", ""),
		types.NewLibrary("raw-body", "2.3.3", ""),
		types.NewLibrary("react-is", "16.8.6", ""),
		types.NewLibrary("react", "16.8.6", ""),
		types.NewLibrary("redux", "4.0.1", ""),
		types.NewLibrary("request", "2.88.0", ""),
		types.NewLibrary("safe-buffer", "5.1.2", ""),
		types.NewLibrary("safer-buffer", "2.1.2", ""),
		types.NewLibrary("scheduler", "0.13.6", ""),
		types.NewLibrary("send", "0.16.2", ""),
		types.NewLibrary("serve-static", "1.13.2", ""),
		types.NewLibrary("setprototypeof", "1.1.0", ""),
		types.NewLibrary("sshpk", "1.16.1", ""),
		types.NewLibrary("statuses", "1.4.0", ""),
		types.NewLibrary("supports-color", "5.5.0", ""),
		types.NewLibrary("symbol-observable", "1.2.0", ""),
		types.NewLibrary("tough-cookie", "2.4.3", ""),
		types.NewLibrary("tunnel-agent", "0.6.0", ""),
		types.NewLibrary("tweetnacl", "0.14.5", ""),
		types.NewLibrary("type-is", "1.6.18", ""),
		types.NewLibrary("unpipe", "1.0.0", ""),
		types.NewLibrary("uri-js", "4.2.2", ""),
		types.NewLibrary("utils-merge", "1.0.1", ""),
		types.NewLibrary("uuid", "3.3.2", ""),
		types.NewLibrary("vary", "1.1.2", ""),
		types.NewLibrary("verror", "1.10.0", ""),
		types.NewLibrary("vue", "2.6.10", ""),
	}

	// manually created
	npmNested = []types.Library{
		types.NewLibrary("debug", "2.0.0", ""),
		types.NewLibrary("debug", "2.6.9", ""),
		types.NewLibrary("ms", "0.6.2", ""),
		types.NewLibrary("ms", "2.0.0", ""),
		types.NewLibrary("ms", "2.1.0", ""),
		types.NewLibrary("ms", "2.1.1", ""),
		types.NewLibrary("send", "0.17.1", ""),
	}
)
