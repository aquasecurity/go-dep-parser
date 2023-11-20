package yarn

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// cd ./pkg/nodejs/yarn
	// docker build -t yarn-test testcase_deps_generator
	// docker run --name node --rm -it yarn-test sh
	// yarn init -y
	// yarn add promise jquery
	// yarn list | grep -E -o "\S+@[^\^~]\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	// to get deps with locations from lock file use following commands:
	// cat yarn.lock | awk '/^\S+@[~^*]?(>= )?[0-9.]*/,/^$/{if($0=="") {print "--"prev} else { if(substr($0,1,2)!="  ") {print NR":"$0} else {print $0}} prev=NR}; END{print "--"prev}' | awk 'BEGIN {s=""}; {(substr($0,1,2)=="--") ? (s=s$0"\n") : (s=s$0)}; END { print s}' | sed -E 's/@([0-9~><*\^]|npm).*version:? "?/:/' | sed 's/  /:/' | sed 's/"//g'| awk 'match($0, /[[:digit:]]+$/) {print substr($0, RSTART, RLENGTH)":"$0 }' |  awk -F":" '{print "{ID: \""$3"@"$4"\", Name: \""$3"\", Version: \""$4"\", Locations: []types.Location{{StartLine: "$2", EndLine: "$1"}}},"}'
	yarnNormal = []types.Library{
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Locations: []types.Location{{StartLine: 5, EndLine: 8}}},
		{ID: "jquery@3.4.1", Name: "jquery", Version: "3.4.1", Locations: []types.Location{{StartLine: 10, EndLine: 13}}},
		{ID: "promise@8.0.3", Name: "promise", Version: "8.0.3", Locations: []types.Location{{StartLine: 15, EndLine: 20}}},
	}

	// ... and
	// yarn --cwd test_deps_generator install
	// node test_deps_generator/index.js yarn.lock
	yarnNormalDeps = []types.Dependency{
		{
			ID: "promise@8.0.3",
			DependsOn: []string{
				"asap@2.0.6",
			},
		},
	}

	// ... and
	// yarn add react redux
	// yarn list | grep -E -o "\S+@[^\^~]\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}'
	// to get deps with locations from lock file use following commands:
	// awk '/^\S+@[~^*]?(>= )?[0-9.]*/,/^$/{if($0=="") {print "--"prev} else { if(substr($0,1,2)!="  ") {print NR":"$0} else {print $0}} prev=NR}; END{print "--"prev}' | awk 'BEGIN {s=""}; {(substr($0,1,2)=="--") ? (s=s$0"\n") : (s=s$0)}; END { print s}' | sed -E 's/@([0-9~><*\^]|npm).*version:? "?/:/' | sed 's/  /:/' | sed 's/"//g'| awk 'match($0, /[[:digit:]]+$/) {print substr($0, RSTART, RLENGTH)":"$0 }' |  awk -F":" '{print "{ID: \""$3"@"$4"\", Name: \""$3"\", Version: \""$4"\", Locations: []types.Location{{StartLine: "$2", EndLine: "$1"}}},"}'
	yarnReact = []types.Library{
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Locations: []types.Location{{StartLine: 5, EndLine: 8}}},
		{ID: "jquery@3.4.1", Name: "jquery", Version: "3.4.1", Locations: []types.Location{{StartLine: 10, EndLine: 13}}},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Locations: []types.Location{{StartLine: 15, EndLine: 18}}},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Locations: []types.Location{{StartLine: 20, EndLine: 25}}},
		{ID: "object-assign@4.1.1", Name: "object-assign", Version: "4.1.1", Locations: []types.Location{{StartLine: 27, EndLine: 30}}},
		{ID: "promise@8.0.3", Name: "promise", Version: "8.0.3", Locations: []types.Location{{StartLine: 32, EndLine: 37}}},
		{ID: "prop-types@15.7.2", Name: "prop-types", Version: "15.7.2", Locations: []types.Location{{StartLine: 39, EndLine: 46}}},
		{ID: "react-is@16.8.6", Name: "react-is", Version: "16.8.6", Locations: []types.Location{{StartLine: 48, EndLine: 51}}},
		{ID: "react@16.8.6", Name: "react", Version: "16.8.6", Locations: []types.Location{{StartLine: 53, EndLine: 61}}},
		{ID: "redux@4.0.1", Name: "redux", Version: "4.0.1", Locations: []types.Location{{StartLine: 63, EndLine: 69}}},
		{ID: "scheduler@0.13.6", Name: "scheduler", Version: "0.13.6", Locations: []types.Location{{StartLine: 71, EndLine: 77}}},
		{ID: "symbol-observable@1.2.0", Name: "symbol-observable", Version: "1.2.0", Locations: []types.Location{{StartLine: 79, EndLine: 82}}},
	}

	// ... and
	// node test_deps_generator/index.js yarn.lock
	yarnReactDeps = []types.Dependency{
		{
			ID: "loose-envify@1.4.0",
			DependsOn: []string{
				"js-tokens@4.0.0",
			},
		},
		{
			ID: "promise@8.0.3",
			DependsOn: []string{
				"asap@2.0.6",
			},
		},
		{
			ID: "prop-types@15.7.2",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"react-is@16.8.6",
			},
		},
		{
			ID: "react@16.8.6",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"prop-types@15.7.2",
				"scheduler@0.13.6",
			},
		},
		{
			ID: "redux@4.0.1",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"symbol-observable@1.2.0",
			},
		},
		{
			ID: "scheduler@0.13.6",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
			},
		},
	}

	// ... and
	// yarn add -D mocha
	// yarn list | grep -E -o "\S+@[^\^~]\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}' | sort | uniq
	// to get deps with locations from lock file use following commands:
	// awk '/^\S+@[~^*]?(>= )?[0-9.]*/,/^$/{if($0=="") {print "--"prev} else { if(substr($0,1,2)!="  ") {print NR":"$0} else {print $0}} prev=NR}; END{print "--"prev}' | awk 'BEGIN {s=""}; {(substr($0,1,2)=="--") ? (s=s$0"\n") : (s=s$0)}; END { print s}' | sed -E 's/@([0-9~><*\^]|npm).*version:? "?/:/' | sed 's/  /:/' | sed 's/"//g'| awk 'match($0, /[[:digit:]]+$/) {print substr($0, RSTART, RLENGTH)":"$0 }' |  awk -F":" '{print "{ID: \""$3"@"$4"\", Name: \""$3"\", Version: \""$4"\", Locations: []types.Location{{StartLine: "$2", EndLine: "$1"}}},"}'
	yarnWithDev = []types.Library{
		{ID: "ansi-colors@3.2.3", Name: "ansi-colors", Version: "3.2.3", Locations: []types.Location{{StartLine: 5, EndLine: 8}}},
		{ID: "ansi-regex@2.1.1", Name: "ansi-regex", Version: "2.1.1", Locations: []types.Location{{StartLine: 10, EndLine: 13}}},
		{ID: "ansi-regex@3.0.0", Name: "ansi-regex", Version: "3.0.0", Locations: []types.Location{{StartLine: 15, EndLine: 18}}},
		{ID: "ansi-regex@4.1.0", Name: "ansi-regex", Version: "4.1.0", Locations: []types.Location{{StartLine: 20, EndLine: 23}}},
		{ID: "ansi-styles@3.2.1", Name: "ansi-styles", Version: "3.2.1", Locations: []types.Location{{StartLine: 25, EndLine: 30}}},
		{ID: "argparse@1.0.10", Name: "argparse", Version: "1.0.10", Locations: []types.Location{{StartLine: 32, EndLine: 37}}},
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Locations: []types.Location{{StartLine: 39, EndLine: 42}}},
		{ID: "balanced-match@1.0.0", Name: "balanced-match", Version: "1.0.0", Locations: []types.Location{{StartLine: 44, EndLine: 47}}},
		{ID: "brace-expansion@1.1.11", Name: "brace-expansion", Version: "1.1.11", Locations: []types.Location{{StartLine: 49, EndLine: 55}}},
		{ID: "browser-stdout@1.3.1", Name: "browser-stdout", Version: "1.3.1", Locations: []types.Location{{StartLine: 57, EndLine: 60}}},
		{ID: "camelcase@5.3.1", Name: "camelcase", Version: "5.3.1", Locations: []types.Location{{StartLine: 62, EndLine: 65}}},
		{ID: "chalk@2.4.2", Name: "chalk", Version: "2.4.2", Locations: []types.Location{{StartLine: 67, EndLine: 74}}},
		{ID: "cliui@4.1.0", Name: "cliui", Version: "4.1.0", Locations: []types.Location{{StartLine: 76, EndLine: 83}}},
		{ID: "code-point-at@1.1.0", Name: "code-point-at", Version: "1.1.0", Locations: []types.Location{{StartLine: 85, EndLine: 88}}},
		{ID: "color-convert@1.9.3", Name: "color-convert", Version: "1.9.3", Locations: []types.Location{{StartLine: 90, EndLine: 95}}},
		{ID: "color-name@1.1.3", Name: "color-name", Version: "1.1.3", Locations: []types.Location{{StartLine: 97, EndLine: 100}}},
		{ID: "concat-map@0.0.1", Name: "concat-map", Version: "0.0.1", Locations: []types.Location{{StartLine: 102, EndLine: 105}}},
		{ID: "cross-spawn@6.0.5", Name: "cross-spawn", Version: "6.0.5", Locations: []types.Location{{StartLine: 107, EndLine: 116}}},
		{ID: "debug@3.2.6", Name: "debug", Version: "3.2.6", Locations: []types.Location{{StartLine: 118, EndLine: 123}}},
		{ID: "decamelize@1.2.0", Name: "decamelize", Version: "1.2.0", Locations: []types.Location{{StartLine: 125, EndLine: 128}}},
		{ID: "define-properties@1.1.3", Name: "define-properties", Version: "1.1.3", Locations: []types.Location{{StartLine: 130, EndLine: 135}}},
		{ID: "diff@3.5.0", Name: "diff", Version: "3.5.0", Locations: []types.Location{{StartLine: 137, EndLine: 140}}},
		{ID: "emoji-regex@7.0.3", Name: "emoji-regex", Version: "7.0.3", Locations: []types.Location{{StartLine: 142, EndLine: 145}}},
		{ID: "end-of-stream@1.4.1", Name: "end-of-stream", Version: "1.4.1", Locations: []types.Location{{StartLine: 147, EndLine: 152}}},
		{ID: "es-abstract@1.13.0", Name: "es-abstract", Version: "1.13.0", Locations: []types.Location{{StartLine: 154, EndLine: 164}}},
		{ID: "es-to-primitive@1.2.0", Name: "es-to-primitive", Version: "1.2.0", Locations: []types.Location{{StartLine: 166, EndLine: 173}}},
		{ID: "escape-string-regexp@1.0.5", Name: "escape-string-regexp", Version: "1.0.5", Locations: []types.Location{{StartLine: 175, EndLine: 178}}},
		{ID: "esprima@4.0.1", Name: "esprima", Version: "4.0.1", Locations: []types.Location{{StartLine: 180, EndLine: 183}}},
		{ID: "execa@1.0.0", Name: "execa", Version: "1.0.0", Locations: []types.Location{{StartLine: 185, EndLine: 196}}},
		{ID: "find-up@3.0.0", Name: "find-up", Version: "3.0.0", Locations: []types.Location{{StartLine: 198, EndLine: 203}}},
		{ID: "flat@4.1.0", Name: "flat", Version: "4.1.0", Locations: []types.Location{{StartLine: 205, EndLine: 210}}},
		{ID: "fs.realpath@1.0.0", Name: "fs.realpath", Version: "1.0.0", Locations: []types.Location{{StartLine: 212, EndLine: 215}}},
		{ID: "function-bind@1.1.1", Name: "function-bind", Version: "1.1.1", Locations: []types.Location{{StartLine: 217, EndLine: 220}}},
		{ID: "get-caller-file@1.0.3", Name: "get-caller-file", Version: "1.0.3", Locations: []types.Location{{StartLine: 222, EndLine: 225}}},
		{ID: "get-caller-file@2.0.5", Name: "get-caller-file", Version: "2.0.5", Locations: []types.Location{{StartLine: 227, EndLine: 230}}},
		{ID: "get-stream@4.1.0", Name: "get-stream", Version: "4.1.0", Locations: []types.Location{{StartLine: 232, EndLine: 237}}},
		{ID: "glob@7.1.3", Name: "glob", Version: "7.1.3", Locations: []types.Location{{StartLine: 239, EndLine: 249}}},
		{ID: "growl@1.10.5", Name: "growl", Version: "1.10.5", Locations: []types.Location{{StartLine: 251, EndLine: 254}}},
		{ID: "has-flag@3.0.0", Name: "has-flag", Version: "3.0.0", Locations: []types.Location{{StartLine: 256, EndLine: 259}}},
		{ID: "has-symbols@1.0.0", Name: "has-symbols", Version: "1.0.0", Locations: []types.Location{{StartLine: 261, EndLine: 264}}},
		{ID: "has@1.0.3", Name: "has", Version: "1.0.3", Locations: []types.Location{{StartLine: 266, EndLine: 271}}},
		{ID: "he@1.2.0", Name: "he", Version: "1.2.0", Locations: []types.Location{{StartLine: 273, EndLine: 276}}},
		{ID: "inflight@1.0.6", Name: "inflight", Version: "1.0.6", Locations: []types.Location{{StartLine: 278, EndLine: 284}}},
		{ID: "inherits@2.0.3", Name: "inherits", Version: "2.0.3", Locations: []types.Location{{StartLine: 286, EndLine: 289}}},
		{ID: "invert-kv@2.0.0", Name: "invert-kv", Version: "2.0.0", Locations: []types.Location{{StartLine: 291, EndLine: 294}}},
		{ID: "is-buffer@2.0.3", Name: "is-buffer", Version: "2.0.3", Locations: []types.Location{{StartLine: 296, EndLine: 299}}},
		{ID: "is-callable@1.1.4", Name: "is-callable", Version: "1.1.4", Locations: []types.Location{{StartLine: 301, EndLine: 304}}},
		{ID: "is-date-object@1.0.1", Name: "is-date-object", Version: "1.0.1", Locations: []types.Location{{StartLine: 306, EndLine: 309}}},
		{ID: "is-fullwidth-code-point@1.0.0", Name: "is-fullwidth-code-point", Version: "1.0.0", Locations: []types.Location{{StartLine: 311, EndLine: 316}}},
		{ID: "is-fullwidth-code-point@2.0.0", Name: "is-fullwidth-code-point", Version: "2.0.0", Locations: []types.Location{{StartLine: 318, EndLine: 321}}},
		{ID: "is-regex@1.0.4", Name: "is-regex", Version: "1.0.4", Locations: []types.Location{{StartLine: 323, EndLine: 328}}},
		{ID: "is-stream@1.1.0", Name: "is-stream", Version: "1.1.0", Locations: []types.Location{{StartLine: 330, EndLine: 333}}},
		{ID: "is-symbol@1.0.2", Name: "is-symbol", Version: "1.0.2", Locations: []types.Location{{StartLine: 335, EndLine: 340}}},
		{ID: "isexe@2.0.0", Name: "isexe", Version: "2.0.0", Locations: []types.Location{{StartLine: 342, EndLine: 345}}},
		{ID: "jquery@3.4.1", Name: "jquery", Version: "3.4.1", Locations: []types.Location{{StartLine: 347, EndLine: 350}}},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Locations: []types.Location{{StartLine: 352, EndLine: 355}}},
		{ID: "js-yaml@3.13.1", Name: "js-yaml", Version: "3.13.1", Locations: []types.Location{{StartLine: 357, EndLine: 363}}},
		{ID: "lcid@2.0.0", Name: "lcid", Version: "2.0.0", Locations: []types.Location{{StartLine: 365, EndLine: 370}}},
		{ID: "locate-path@3.0.0", Name: "locate-path", Version: "3.0.0", Locations: []types.Location{{StartLine: 372, EndLine: 378}}},
		{ID: "lodash@4.17.11", Name: "lodash", Version: "4.17.11", Locations: []types.Location{{StartLine: 380, EndLine: 383}}},
		{ID: "log-symbols@2.2.0", Name: "log-symbols", Version: "2.2.0", Locations: []types.Location{{StartLine: 385, EndLine: 390}}},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Locations: []types.Location{{StartLine: 392, EndLine: 397}}},
		{ID: "map-age-cleaner@0.1.3", Name: "map-age-cleaner", Version: "0.1.3", Locations: []types.Location{{StartLine: 399, EndLine: 404}}},
		{ID: "mem@4.3.0", Name: "mem", Version: "4.3.0", Locations: []types.Location{{StartLine: 406, EndLine: 413}}},
		{ID: "mimic-fn@2.1.0", Name: "mimic-fn", Version: "2.1.0", Locations: []types.Location{{StartLine: 415, EndLine: 418}}},
		{ID: "minimatch@3.0.4", Name: "minimatch", Version: "3.0.4", Locations: []types.Location{{StartLine: 420, EndLine: 425}}},
		{ID: "minimist@0.0.8", Name: "minimist", Version: "0.0.8", Locations: []types.Location{{StartLine: 427, EndLine: 430}}},
		{ID: "mkdirp@0.5.1", Name: "mkdirp", Version: "0.5.1", Locations: []types.Location{{StartLine: 432, EndLine: 437}}},
		{ID: "mocha@6.1.4", Name: "mocha", Version: "6.1.4", Locations: []types.Location{{StartLine: 439, EndLine: 466}}},
		{ID: "ms@2.1.1", Name: "ms", Version: "2.1.1", Locations: []types.Location{{StartLine: 468, EndLine: 471}}},
		{ID: "nice-try@1.0.5", Name: "nice-try", Version: "1.0.5", Locations: []types.Location{{StartLine: 473, EndLine: 476}}},
		{ID: "node-environment-flags@1.0.5", Name: "node-environment-flags", Version: "1.0.5", Locations: []types.Location{{StartLine: 478, EndLine: 484}}},
		{ID: "npm-run-path@2.0.2", Name: "npm-run-path", Version: "2.0.2", Locations: []types.Location{{StartLine: 486, EndLine: 491}}},
		{ID: "number-is-nan@1.0.1", Name: "number-is-nan", Version: "1.0.1", Locations: []types.Location{{StartLine: 493, EndLine: 496}}},
		{ID: "object-assign@4.1.1", Name: "object-assign", Version: "4.1.1", Locations: []types.Location{{StartLine: 498, EndLine: 501}}},
		{ID: "object-keys@1.1.1", Name: "object-keys", Version: "1.1.1", Locations: []types.Location{{StartLine: 503, EndLine: 506}}},
		{ID: "object.assign@4.1.0", Name: "object.assign", Version: "4.1.0", Locations: []types.Location{{StartLine: 508, EndLine: 516}}},
		{ID: "object.getownpropertydescriptors@2.0.3", Name: "object.getownpropertydescriptors", Version: "2.0.3", Locations: []types.Location{{StartLine: 518, EndLine: 524}}},
		{ID: "once@1.4.0", Name: "once", Version: "1.4.0", Locations: []types.Location{{StartLine: 526, EndLine: 531}}},
		{ID: "os-locale@3.1.0", Name: "os-locale", Version: "3.1.0", Locations: []types.Location{{StartLine: 533, EndLine: 540}}},
		{ID: "p-defer@1.0.0", Name: "p-defer", Version: "1.0.0", Locations: []types.Location{{StartLine: 542, EndLine: 545}}},
		{ID: "p-finally@1.0.0", Name: "p-finally", Version: "1.0.0", Locations: []types.Location{{StartLine: 547, EndLine: 550}}},
		{ID: "p-is-promise@2.1.0", Name: "p-is-promise", Version: "2.1.0", Locations: []types.Location{{StartLine: 552, EndLine: 555}}},
		{ID: "p-limit@2.2.0", Name: "p-limit", Version: "2.2.0", Locations: []types.Location{{StartLine: 557, EndLine: 562}}},
		{ID: "p-locate@3.0.0", Name: "p-locate", Version: "3.0.0", Locations: []types.Location{{StartLine: 564, EndLine: 569}}},
		{ID: "p-try@2.2.0", Name: "p-try", Version: "2.2.0", Locations: []types.Location{{StartLine: 571, EndLine: 574}}},
		{ID: "path-exists@3.0.0", Name: "path-exists", Version: "3.0.0", Locations: []types.Location{{StartLine: 576, EndLine: 579}}},
		{ID: "path-is-absolute@1.0.1", Name: "path-is-absolute", Version: "1.0.1", Locations: []types.Location{{StartLine: 581, EndLine: 584}}},
		{ID: "path-key@2.0.1", Name: "path-key", Version: "2.0.1", Locations: []types.Location{{StartLine: 586, EndLine: 589}}},
		{ID: "promise@8.0.3", Name: "promise", Version: "8.0.3", Locations: []types.Location{{StartLine: 591, EndLine: 596}}},
		{ID: "prop-types@15.7.2", Name: "prop-types", Version: "15.7.2", Locations: []types.Location{{StartLine: 598, EndLine: 605}}},
		{ID: "pump@3.0.0", Name: "pump", Version: "3.0.0", Locations: []types.Location{{StartLine: 607, EndLine: 613}}},
		{ID: "react-is@16.8.6", Name: "react-is", Version: "16.8.6", Locations: []types.Location{{StartLine: 615, EndLine: 618}}},
		{ID: "react@16.8.6", Name: "react", Version: "16.8.6", Locations: []types.Location{{StartLine: 620, EndLine: 628}}},
		{ID: "redux@4.0.1", Name: "redux", Version: "4.0.1", Locations: []types.Location{{StartLine: 630, EndLine: 636}}},
		{ID: "require-directory@2.1.1", Name: "require-directory", Version: "2.1.1", Locations: []types.Location{{StartLine: 638, EndLine: 641}}},
		{ID: "require-main-filename@1.0.1", Name: "require-main-filename", Version: "1.0.1", Locations: []types.Location{{StartLine: 643, EndLine: 646}}},
		{ID: "require-main-filename@2.0.0", Name: "require-main-filename", Version: "2.0.0", Locations: []types.Location{{StartLine: 648, EndLine: 651}}},
		{ID: "scheduler@0.13.6", Name: "scheduler", Version: "0.13.6", Locations: []types.Location{{StartLine: 653, EndLine: 659}}},
		{ID: "semver@5.7.0", Name: "semver", Version: "5.7.0", Locations: []types.Location{{StartLine: 661, EndLine: 664}}},
		{ID: "set-blocking@2.0.0", Name: "set-blocking", Version: "2.0.0", Locations: []types.Location{{StartLine: 666, EndLine: 669}}},
		{ID: "shebang-command@1.2.0", Name: "shebang-command", Version: "1.2.0", Locations: []types.Location{{StartLine: 671, EndLine: 676}}},
		{ID: "shebang-regex@1.0.0", Name: "shebang-regex", Version: "1.0.0", Locations: []types.Location{{StartLine: 678, EndLine: 681}}},
		{ID: "signal-exit@3.0.2", Name: "signal-exit", Version: "3.0.2", Locations: []types.Location{{StartLine: 683, EndLine: 686}}},
		{ID: "sprintf-js@1.0.3", Name: "sprintf-js", Version: "1.0.3", Locations: []types.Location{{StartLine: 688, EndLine: 691}}},
		{ID: "string-width@1.0.2", Name: "string-width", Version: "1.0.2", Locations: []types.Location{{StartLine: 693, EndLine: 700}}},
		{ID: "string-width@2.1.1", Name: "string-width", Version: "2.1.1", Locations: []types.Location{{StartLine: 702, EndLine: 708}}},
		{ID: "string-width@3.1.0", Name: "string-width", Version: "3.1.0", Locations: []types.Location{{StartLine: 710, EndLine: 717}}},
		{ID: "strip-ansi@3.0.1", Name: "strip-ansi", Version: "3.0.1", Locations: []types.Location{{StartLine: 719, EndLine: 724}}},
		{ID: "strip-ansi@4.0.0", Name: "strip-ansi", Version: "4.0.0", Locations: []types.Location{{StartLine: 726, EndLine: 731}}},
		{ID: "strip-ansi@5.2.0", Name: "strip-ansi", Version: "5.2.0", Locations: []types.Location{{StartLine: 733, EndLine: 738}}},
		{ID: "strip-eof@1.0.0", Name: "strip-eof", Version: "1.0.0", Locations: []types.Location{{StartLine: 740, EndLine: 743}}},
		{ID: "strip-json-comments@2.0.1", Name: "strip-json-comments", Version: "2.0.1", Locations: []types.Location{{StartLine: 745, EndLine: 748}}},
		{ID: "supports-color@6.0.0", Name: "supports-color", Version: "6.0.0", Locations: []types.Location{{StartLine: 750, EndLine: 755}}},
		{ID: "supports-color@5.5.0", Name: "supports-color", Version: "5.5.0", Locations: []types.Location{{StartLine: 757, EndLine: 762}}},
		{ID: "symbol-observable@1.2.0", Name: "symbol-observable", Version: "1.2.0", Locations: []types.Location{{StartLine: 764, EndLine: 767}}},
		{ID: "which-module@2.0.0", Name: "which-module", Version: "2.0.0", Locations: []types.Location{{StartLine: 769, EndLine: 772}}},
		{ID: "which@1.3.1", Name: "which", Version: "1.3.1", Locations: []types.Location{{StartLine: 774, EndLine: 779}}},
		{ID: "wide-align@1.1.3", Name: "wide-align", Version: "1.1.3", Locations: []types.Location{{StartLine: 781, EndLine: 786}}},
		{ID: "wrap-ansi@2.1.0", Name: "wrap-ansi", Version: "2.1.0", Locations: []types.Location{{StartLine: 788, EndLine: 794}}},
		{ID: "wrappy@1.0.2", Name: "wrappy", Version: "1.0.2", Locations: []types.Location{{StartLine: 796, EndLine: 799}}},
		{ID: "y18n@4.0.0", Name: "y18n", Version: "4.0.0", Locations: []types.Location{{StartLine: 801, EndLine: 804}}},
		{ID: "yargs-parser@13.0.0", Name: "yargs-parser", Version: "13.0.0", Locations: []types.Location{{StartLine: 806, EndLine: 812}}},
		{ID: "yargs-parser@11.1.1", Name: "yargs-parser", Version: "11.1.1", Locations: []types.Location{{StartLine: 814, EndLine: 820}}},
		{ID: "yargs-parser@13.1.0", Name: "yargs-parser", Version: "13.1.0", Locations: []types.Location{{StartLine: 822, EndLine: 828}}},
		{ID: "yargs-unparser@1.5.0", Name: "yargs-unparser", Version: "1.5.0", Locations: []types.Location{{StartLine: 830, EndLine: 837}}},
		{ID: "yargs@13.2.2", Name: "yargs", Version: "13.2.2", Locations: []types.Location{{StartLine: 839, EndLine: 854}}},
		{ID: "yargs@12.0.5", Name: "yargs", Version: "12.0.5", Locations: []types.Location{{StartLine: 856, EndLine: 872}}},
	}

	// ... and
	// node test_deps_generator/index.js yarn.lock
	yarnWithDevDeps = []types.Dependency{
		{
			ID: "ansi-styles@3.2.1",
			DependsOn: []string{
				"color-convert@1.9.3",
			},
		},
		{
			ID: "argparse@1.0.10",
			DependsOn: []string{
				"sprintf-js@1.0.3",
			},
		},
		{
			ID: "brace-expansion@1.1.11",
			DependsOn: []string{
				"balanced-match@1.0.0",
				"concat-map@0.0.1",
			},
		},
		{
			ID: "chalk@2.4.2",
			DependsOn: []string{
				"ansi-styles@3.2.1",
				"escape-string-regexp@1.0.5",
				"supports-color@5.5.0",
			},
		},
		{
			ID: "cliui@4.1.0",
			DependsOn: []string{
				"string-width@2.1.1",
				"strip-ansi@4.0.0",
				"wrap-ansi@2.1.0",
			},
		},
		{
			ID: "color-convert@1.9.3",
			DependsOn: []string{
				"color-name@1.1.3",
			},
		},
		{
			ID: "cross-spawn@6.0.5",
			DependsOn: []string{
				"nice-try@1.0.5",
				"path-key@2.0.1",
				"semver@5.7.0",
				"shebang-command@1.2.0",
				"which@1.3.1",
			},
		},
		{
			ID: "debug@3.2.6",
			DependsOn: []string{
				"ms@2.1.1",
			},
		},
		{
			ID: "define-properties@1.1.3",
			DependsOn: []string{
				"object-keys@1.1.1",
			},
		},
		{
			ID: "end-of-stream@1.4.1",
			DependsOn: []string{
				"once@1.4.0",
			},
		},
		{
			ID: "es-abstract@1.13.0",
			DependsOn: []string{
				"es-to-primitive@1.2.0",
				"function-bind@1.1.1",
				"has@1.0.3",
				"is-callable@1.1.4",
				"is-regex@1.0.4",
				"object-keys@1.1.1",
			},
		},
		{
			ID: "es-to-primitive@1.2.0",
			DependsOn: []string{
				"is-callable@1.1.4",
				"is-date-object@1.0.1",
				"is-symbol@1.0.2",
			},
		},
		{
			ID: "execa@1.0.0",
			DependsOn: []string{
				"cross-spawn@6.0.5",
				"get-stream@4.1.0",
				"is-stream@1.1.0",
				"npm-run-path@2.0.2",
				"p-finally@1.0.0",
				"signal-exit@3.0.2",
				"strip-eof@1.0.0",
			},
		},
		{
			ID: "find-up@3.0.0",
			DependsOn: []string{
				"locate-path@3.0.0",
			},
		},
		{
			ID: "flat@4.1.0",
			DependsOn: []string{
				"is-buffer@2.0.3",
			},
		},
		{
			ID: "get-stream@4.1.0",
			DependsOn: []string{
				"pump@3.0.0",
			},
		},
		{
			ID: "glob@7.1.3",
			DependsOn: []string{
				"fs.realpath@1.0.0",
				"inflight@1.0.6",
				"inherits@2.0.3",
				"minimatch@3.0.4",
				"once@1.4.0",
				"path-is-absolute@1.0.1",
			},
		},
		{
			ID: "has@1.0.3",
			DependsOn: []string{
				"function-bind@1.1.1",
			},
		},
		{
			ID: "inflight@1.0.6",
			DependsOn: []string{
				"once@1.4.0",
				"wrappy@1.0.2",
			},
		},
		{
			ID: "is-fullwidth-code-point@1.0.0",
			DependsOn: []string{
				"number-is-nan@1.0.1",
			},
		},
		{
			ID: "is-regex@1.0.4",
			DependsOn: []string{
				"has@1.0.3",
			},
		},
		{
			ID: "is-symbol@1.0.2",
			DependsOn: []string{
				"has-symbols@1.0.0",
			},
		},
		{
			ID: "js-yaml@3.13.1",
			DependsOn: []string{
				"argparse@1.0.10",
				"esprima@4.0.1",
			},
		},
		{
			ID: "lcid@2.0.0",
			DependsOn: []string{
				"invert-kv@2.0.0",
			},
		},
		{
			ID: "locate-path@3.0.0",
			DependsOn: []string{
				"p-locate@3.0.0",
				"path-exists@3.0.0",
			},
		},
		{
			ID: "log-symbols@2.2.0",
			DependsOn: []string{
				"chalk@2.4.2",
			},
		},
		{
			ID: "loose-envify@1.4.0",
			DependsOn: []string{
				"js-tokens@4.0.0",
			},
		},
		{
			ID: "map-age-cleaner@0.1.3",
			DependsOn: []string{
				"p-defer@1.0.0",
			},
		},
		{
			ID: "mem@4.3.0",
			DependsOn: []string{
				"map-age-cleaner@0.1.3",
				"mimic-fn@2.1.0",
				"p-is-promise@2.1.0",
			},
		},
		{
			ID: "minimatch@3.0.4",
			DependsOn: []string{
				"brace-expansion@1.1.11",
			},
		},
		{
			ID: "mkdirp@0.5.1",
			DependsOn: []string{
				"minimist@0.0.8",
			},
		},
		{
			ID: "mocha@6.1.4",
			DependsOn: []string{
				"ansi-colors@3.2.3",
				"browser-stdout@1.3.1",
				"debug@3.2.6",
				"diff@3.5.0",
				"escape-string-regexp@1.0.5",
				"find-up@3.0.0",
				"glob@7.1.3",
				"growl@1.10.5",
				"he@1.2.0",
				"js-yaml@3.13.1",
				"log-symbols@2.2.0",
				"minimatch@3.0.4",
				"mkdirp@0.5.1",
				"ms@2.1.1",
				"node-environment-flags@1.0.5",
				"object.assign@4.1.0",
				"strip-json-comments@2.0.1",
				"supports-color@6.0.0",
				"which@1.3.1",
				"wide-align@1.1.3",
				"yargs@13.2.2",
				"yargs-parser@13.0.0",
				"yargs-unparser@1.5.0",
			},
		},
		{
			ID: "node-environment-flags@1.0.5",
			DependsOn: []string{
				"object.getownpropertydescriptors@2.0.3",
				"semver@5.7.0",
			},
		},
		{
			ID: "npm-run-path@2.0.2",
			DependsOn: []string{
				"path-key@2.0.1",
			},
		},
		{
			ID: "object.assign@4.1.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"function-bind@1.1.1",
				"has-symbols@1.0.0",
				"object-keys@1.1.1",
			},
		},
		{
			ID: "object.getownpropertydescriptors@2.0.3",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
			},
		},
		{
			ID: "once@1.4.0",
			DependsOn: []string{
				"wrappy@1.0.2",
			},
		},
		{
			ID: "os-locale@3.1.0",
			DependsOn: []string{
				"execa@1.0.0",
				"lcid@2.0.0",
				"mem@4.3.0",
			},
		},
		{
			ID: "p-limit@2.2.0",
			DependsOn: []string{
				"p-try@2.2.0",
			},
		},
		{
			ID: "p-locate@3.0.0",
			DependsOn: []string{
				"p-limit@2.2.0",
			},
		},
		{
			ID: "promise@8.0.3",
			DependsOn: []string{
				"asap@2.0.6",
			},
		},
		{
			ID: "prop-types@15.7.2",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"react-is@16.8.6",
			},
		},
		{
			ID: "pump@3.0.0",
			DependsOn: []string{
				"end-of-stream@1.4.1",
				"once@1.4.0",
			},
		},
		{
			ID: "react@16.8.6",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"prop-types@15.7.2",
				"scheduler@0.13.6",
			},
		},
		{
			ID: "redux@4.0.1",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"symbol-observable@1.2.0",
			},
		},
		{
			ID: "scheduler@0.13.6",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
			},
		},
		{
			ID: "shebang-command@1.2.0",
			DependsOn: []string{
				"shebang-regex@1.0.0",
			},
		},
		{
			ID: "string-width@1.0.2",
			DependsOn: []string{
				"code-point-at@1.1.0",
				"is-fullwidth-code-point@1.0.0",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID: "string-width@2.1.1",
			DependsOn: []string{
				"is-fullwidth-code-point@2.0.0",
				"strip-ansi@4.0.0",
			},
		},
		{
			ID: "string-width@3.1.0",
			DependsOn: []string{
				"emoji-regex@7.0.3",
				"is-fullwidth-code-point@2.0.0",
				"strip-ansi@5.2.0",
			},
		},
		{
			ID: "strip-ansi@3.0.1",
			DependsOn: []string{
				"ansi-regex@2.1.1",
			},
		},
		{
			ID: "strip-ansi@4.0.0",
			DependsOn: []string{
				"ansi-regex@3.0.0",
			},
		},
		{
			ID: "strip-ansi@5.2.0",
			DependsOn: []string{
				"ansi-regex@4.1.0",
			},
		},
		{
			ID: "supports-color@6.0.0",
			DependsOn: []string{
				"has-flag@3.0.0",
			},
		},
		{
			ID: "supports-color@5.5.0",
			DependsOn: []string{
				"has-flag@3.0.0",
			},
		},
		{
			ID: "which@1.3.1",
			DependsOn: []string{
				"isexe@2.0.0",
			},
		},
		{
			ID: "wide-align@1.1.3",
			DependsOn: []string{
				"string-width@2.1.1",
			},
		},
		{
			ID: "wrap-ansi@2.1.0",
			DependsOn: []string{
				"string-width@1.0.2",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID: "yargs-parser@13.0.0",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
			},
		},
		{
			ID: "yargs-parser@11.1.1",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
			},
		},
		{
			ID: "yargs-parser@13.1.0",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
			},
		},
		{
			ID: "yargs-unparser@1.5.0",
			DependsOn: []string{
				"flat@4.1.0",
				"lodash@4.17.11",
				"yargs@12.0.5",
			},
		},
		{
			ID: "yargs@13.2.2",
			DependsOn: []string{
				"cliui@4.1.0",
				"find-up@3.0.0",
				"get-caller-file@2.0.5",
				"os-locale@3.1.0",
				"require-directory@2.1.1",
				"require-main-filename@2.0.0",
				"set-blocking@2.0.0",
				"string-width@3.1.0",
				"which-module@2.0.0",
				"y18n@4.0.0",
				"yargs-parser@13.1.0",
			},
		},
		{
			ID: "yargs@12.0.5",
			DependsOn: []string{
				"cliui@4.1.0",
				"decamelize@1.2.0",
				"find-up@3.0.0",
				"get-caller-file@1.0.3",
				"os-locale@3.1.0",
				"require-directory@2.1.1",
				"require-main-filename@1.0.1",
				"set-blocking@2.0.0",
				"string-width@2.1.1",
				"which-module@2.0.0",
				"y18n@4.0.0",
				"yargs-parser@11.1.1",
			},
		},
	}

	// ... and
	// yarn add lodash request chalk commander express async axios vue
	// yarn list | grep -E -o "\S+@[^\^~]\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}' | sort | uniq
	// to get deps with locations from lock file use following commands:
	// awk '/^\S+@[~^*]?(>= )?[0-9.]*/,/^$/{if($0=="") {print "--"prev} else { if(substr($0,1,2)!="  ") {print NR":"$0} else {print $0}} prev=NR}; END{print "--"prev}' | awk 'BEGIN {s=""}; {(substr($0,1,2)=="--") ? (s=s$0"\n") : (s=s$0)}; END { print s}' | sed -E 's/@([0-9~><*\^]|npm).*version:? "?/:/' | sed 's/  /:/' | sed 's/"//g'| awk 'match($0, /[[:digit:]]+$/) {print substr($0, RSTART, RLENGTH)":"$0 }' |  awk -F":" '{print "{ID: \""$3"@"$4"\", Name: \""$3"\", Version: \""$4"\", Locations: []types.Location{{StartLine: "$2", EndLine: "$1"}}},"}'
	yarnMany = []types.Library{
		{ID: "accepts@1.3.7", Name: "accepts", Version: "1.3.7", Locations: []types.Location{{StartLine: 5, EndLine: 11}}},
		{ID: "ajv@6.10.0", Name: "ajv", Version: "6.10.0", Locations: []types.Location{{StartLine: 13, EndLine: 21}}},
		{ID: "ansi-colors@3.2.3", Name: "ansi-colors", Version: "3.2.3", Locations: []types.Location{{StartLine: 23, EndLine: 26}}},
		{ID: "ansi-regex@2.1.1", Name: "ansi-regex", Version: "2.1.1", Locations: []types.Location{{StartLine: 28, EndLine: 31}}},
		{ID: "ansi-regex@3.0.0", Name: "ansi-regex", Version: "3.0.0", Locations: []types.Location{{StartLine: 33, EndLine: 36}}},
		{ID: "ansi-regex@4.1.0", Name: "ansi-regex", Version: "4.1.0", Locations: []types.Location{{StartLine: 38, EndLine: 41}}},
		{ID: "ansi-styles@3.2.1", Name: "ansi-styles", Version: "3.2.1", Locations: []types.Location{{StartLine: 43, EndLine: 48}}},
		{ID: "argparse@1.0.10", Name: "argparse", Version: "1.0.10", Locations: []types.Location{{StartLine: 50, EndLine: 55}}},
		{ID: "array-flatten@1.1.1", Name: "array-flatten", Version: "1.1.1", Locations: []types.Location{{StartLine: 57, EndLine: 60}}},
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Locations: []types.Location{{StartLine: 62, EndLine: 65}}},
		{ID: "asn1@0.2.4", Name: "asn1", Version: "0.2.4", Locations: []types.Location{{StartLine: 67, EndLine: 72}}},
		{ID: "assert-plus@1.0.0", Name: "assert-plus", Version: "1.0.0", Locations: []types.Location{{StartLine: 74, EndLine: 77}}},
		{ID: "async@2.6.2", Name: "async", Version: "2.6.2", Locations: []types.Location{{StartLine: 79, EndLine: 84}}},
		{ID: "asynckit@0.4.0", Name: "asynckit", Version: "0.4.0", Locations: []types.Location{{StartLine: 86, EndLine: 89}}},
		{ID: "aws-sign2@0.7.0", Name: "aws-sign2", Version: "0.7.0", Locations: []types.Location{{StartLine: 91, EndLine: 94}}},
		{ID: "aws4@1.8.0", Name: "aws4", Version: "1.8.0", Locations: []types.Location{{StartLine: 96, EndLine: 99}}},
		{ID: "axios@0.18.0", Name: "axios", Version: "0.18.0", Locations: []types.Location{{StartLine: 101, EndLine: 107}}},
		{ID: "balanced-match@1.0.0", Name: "balanced-match", Version: "1.0.0", Locations: []types.Location{{StartLine: 109, EndLine: 112}}},
		{ID: "bcrypt-pbkdf@1.0.2", Name: "bcrypt-pbkdf", Version: "1.0.2", Locations: []types.Location{{StartLine: 114, EndLine: 119}}},
		{ID: "body-parser@1.18.3", Name: "body-parser", Version: "1.18.3", Locations: []types.Location{{StartLine: 121, EndLine: 135}}},
		{ID: "brace-expansion@1.1.11", Name: "brace-expansion", Version: "1.1.11", Locations: []types.Location{{StartLine: 137, EndLine: 143}}},
		{ID: "browser-stdout@1.3.1", Name: "browser-stdout", Version: "1.3.1", Locations: []types.Location{{StartLine: 145, EndLine: 148}}},
		{ID: "bytes@3.0.0", Name: "bytes", Version: "3.0.0", Locations: []types.Location{{StartLine: 150, EndLine: 153}}},
		{ID: "camelcase@5.3.1", Name: "camelcase", Version: "5.3.1", Locations: []types.Location{{StartLine: 155, EndLine: 158}}},
		{ID: "caseless@0.12.0", Name: "caseless", Version: "0.12.0", Locations: []types.Location{{StartLine: 160, EndLine: 163}}},
		{ID: "chalk@2.4.2", Name: "chalk", Version: "2.4.2", Locations: []types.Location{{StartLine: 165, EndLine: 172}}},
		{ID: "cliui@4.1.0", Name: "cliui", Version: "4.1.0", Locations: []types.Location{{StartLine: 174, EndLine: 181}}},
		{ID: "code-point-at@1.1.0", Name: "code-point-at", Version: "1.1.0", Locations: []types.Location{{StartLine: 183, EndLine: 186}}},
		{ID: "color-convert@1.9.3", Name: "color-convert", Version: "1.9.3", Locations: []types.Location{{StartLine: 188, EndLine: 193}}},
		{ID: "color-name@1.1.3", Name: "color-name", Version: "1.1.3", Locations: []types.Location{{StartLine: 195, EndLine: 198}}},
		{ID: "combined-stream@1.0.8", Name: "combined-stream", Version: "1.0.8", Locations: []types.Location{{StartLine: 200, EndLine: 205}}},
		{ID: "commander@2.20.0", Name: "commander", Version: "2.20.0", Locations: []types.Location{{StartLine: 207, EndLine: 210}}},
		{ID: "concat-map@0.0.1", Name: "concat-map", Version: "0.0.1", Locations: []types.Location{{StartLine: 212, EndLine: 215}}},
		{ID: "content-disposition@0.5.2", Name: "content-disposition", Version: "0.5.2", Locations: []types.Location{{StartLine: 217, EndLine: 220}}},
		{ID: "content-type@1.0.4", Name: "content-type", Version: "1.0.4", Locations: []types.Location{{StartLine: 222, EndLine: 225}}},
		{ID: "cookie-signature@1.0.6", Name: "cookie-signature", Version: "1.0.6", Locations: []types.Location{{StartLine: 227, EndLine: 230}}},
		{ID: "cookie@0.3.1", Name: "cookie", Version: "0.3.1", Locations: []types.Location{{StartLine: 232, EndLine: 235}}},
		{ID: "core-util-is@1.0.2", Name: "core-util-is", Version: "1.0.2", Locations: []types.Location{{StartLine: 237, EndLine: 240}}},
		{ID: "cross-spawn@6.0.5", Name: "cross-spawn", Version: "6.0.5", Locations: []types.Location{{StartLine: 242, EndLine: 251}}},
		{ID: "dashdash@1.14.1", Name: "dashdash", Version: "1.14.1", Locations: []types.Location{{StartLine: 253, EndLine: 258}}},
		{ID: "debug@2.6.9", Name: "debug", Version: "2.6.9", Locations: []types.Location{{StartLine: 260, EndLine: 265}}},
		{ID: "debug@3.2.6", Name: "debug", Version: "3.2.6", Locations: []types.Location{{StartLine: 267, EndLine: 272}}},
		{ID: "decamelize@1.2.0", Name: "decamelize", Version: "1.2.0", Locations: []types.Location{{StartLine: 274, EndLine: 277}}},
		{ID: "define-properties@1.1.3", Name: "define-properties", Version: "1.1.3", Locations: []types.Location{{StartLine: 279, EndLine: 284}}},
		{ID: "delayed-stream@1.0.0", Name: "delayed-stream", Version: "1.0.0", Locations: []types.Location{{StartLine: 286, EndLine: 289}}},
		{ID: "depd@1.1.2", Name: "depd", Version: "1.1.2", Locations: []types.Location{{StartLine: 291, EndLine: 294}}},
		{ID: "destroy@1.0.4", Name: "destroy", Version: "1.0.4", Locations: []types.Location{{StartLine: 296, EndLine: 299}}},
		{ID: "diff@3.5.0", Name: "diff", Version: "3.5.0", Locations: []types.Location{{StartLine: 301, EndLine: 304}}},
		{ID: "ecc-jsbn@0.1.2", Name: "ecc-jsbn", Version: "0.1.2", Locations: []types.Location{{StartLine: 306, EndLine: 312}}},
		{ID: "ee-first@1.1.1", Name: "ee-first", Version: "1.1.1", Locations: []types.Location{{StartLine: 314, EndLine: 317}}},
		{ID: "emoji-regex@7.0.3", Name: "emoji-regex", Version: "7.0.3", Locations: []types.Location{{StartLine: 319, EndLine: 322}}},
		{ID: "encodeurl@1.0.2", Name: "encodeurl", Version: "1.0.2", Locations: []types.Location{{StartLine: 324, EndLine: 327}}},
		{ID: "end-of-stream@1.4.1", Name: "end-of-stream", Version: "1.4.1", Locations: []types.Location{{StartLine: 329, EndLine: 334}}},
		{ID: "es-abstract@1.13.0", Name: "es-abstract", Version: "1.13.0", Locations: []types.Location{{StartLine: 336, EndLine: 346}}},
		{ID: "es-to-primitive@1.2.0", Name: "es-to-primitive", Version: "1.2.0", Locations: []types.Location{{StartLine: 348, EndLine: 355}}},
		{ID: "escape-html@1.0.3", Name: "escape-html", Version: "1.0.3", Locations: []types.Location{{StartLine: 357, EndLine: 360}}},
		{ID: "escape-string-regexp@1.0.5", Name: "escape-string-regexp", Version: "1.0.5", Locations: []types.Location{{StartLine: 362, EndLine: 365}}},
		{ID: "esprima@4.0.1", Name: "esprima", Version: "4.0.1", Locations: []types.Location{{StartLine: 367, EndLine: 370}}},
		{ID: "etag@1.8.1", Name: "etag", Version: "1.8.1", Locations: []types.Location{{StartLine: 372, EndLine: 375}}},
		{ID: "execa@1.0.0", Name: "execa", Version: "1.0.0", Locations: []types.Location{{StartLine: 377, EndLine: 388}}},
		{ID: "express@4.16.4", Name: "express", Version: "4.16.4", Locations: []types.Location{{StartLine: 390, EndLine: 424}}},
		{ID: "extend@3.0.2", Name: "extend", Version: "3.0.2", Locations: []types.Location{{StartLine: 426, EndLine: 429}}},
		{ID: "extsprintf@1.3.0", Name: "extsprintf", Version: "1.3.0", Locations: []types.Location{{StartLine: 431, EndLine: 434}}},
		{ID: "extsprintf@1.4.0", Name: "extsprintf", Version: "1.4.0", Locations: []types.Location{{StartLine: 436, EndLine: 439}}},
		{ID: "fast-deep-equal@2.0.1", Name: "fast-deep-equal", Version: "2.0.1", Locations: []types.Location{{StartLine: 441, EndLine: 444}}},
		{ID: "fast-json-stable-stringify@2.0.0", Name: "fast-json-stable-stringify", Version: "2.0.0", Locations: []types.Location{{StartLine: 446, EndLine: 449}}},
		{ID: "finalhandler@1.1.1", Name: "finalhandler", Version: "1.1.1", Locations: []types.Location{{StartLine: 451, EndLine: 462}}},
		{ID: "find-up@3.0.0", Name: "find-up", Version: "3.0.0", Locations: []types.Location{{StartLine: 464, EndLine: 469}}},
		{ID: "flat@4.1.0", Name: "flat", Version: "4.1.0", Locations: []types.Location{{StartLine: 471, EndLine: 476}}},
		{ID: "follow-redirects@1.7.0", Name: "follow-redirects", Version: "1.7.0", Locations: []types.Location{{StartLine: 478, EndLine: 483}}},
		{ID: "forever-agent@0.6.1", Name: "forever-agent", Version: "0.6.1", Locations: []types.Location{{StartLine: 485, EndLine: 488}}},
		{ID: "form-data@2.3.3", Name: "form-data", Version: "2.3.3", Locations: []types.Location{{StartLine: 490, EndLine: 497}}},
		{ID: "forwarded@0.1.2", Name: "forwarded", Version: "0.1.2", Locations: []types.Location{{StartLine: 499, EndLine: 502}}},
		{ID: "fresh@0.5.2", Name: "fresh", Version: "0.5.2", Locations: []types.Location{{StartLine: 504, EndLine: 507}}},
		{ID: "fs.realpath@1.0.0", Name: "fs.realpath", Version: "1.0.0", Locations: []types.Location{{StartLine: 509, EndLine: 512}}},
		{ID: "function-bind@1.1.1", Name: "function-bind", Version: "1.1.1", Locations: []types.Location{{StartLine: 514, EndLine: 517}}},
		{ID: "get-caller-file@1.0.3", Name: "get-caller-file", Version: "1.0.3", Locations: []types.Location{{StartLine: 519, EndLine: 522}}},
		{ID: "get-caller-file@2.0.5", Name: "get-caller-file", Version: "2.0.5", Locations: []types.Location{{StartLine: 524, EndLine: 527}}},
		{ID: "get-stream@4.1.0", Name: "get-stream", Version: "4.1.0", Locations: []types.Location{{StartLine: 529, EndLine: 534}}},
		{ID: "getpass@0.1.7", Name: "getpass", Version: "0.1.7", Locations: []types.Location{{StartLine: 536, EndLine: 541}}},
		{ID: "glob@7.1.3", Name: "glob", Version: "7.1.3", Locations: []types.Location{{StartLine: 543, EndLine: 553}}},
		{ID: "growl@1.10.5", Name: "growl", Version: "1.10.5", Locations: []types.Location{{StartLine: 555, EndLine: 558}}},
		{ID: "har-schema@2.0.0", Name: "har-schema", Version: "2.0.0", Locations: []types.Location{{StartLine: 560, EndLine: 563}}},
		{ID: "har-validator@5.1.3", Name: "har-validator", Version: "5.1.3", Locations: []types.Location{{StartLine: 565, EndLine: 571}}},
		{ID: "has-flag@3.0.0", Name: "has-flag", Version: "3.0.0", Locations: []types.Location{{StartLine: 573, EndLine: 576}}},
		{ID: "has-symbols@1.0.0", Name: "has-symbols", Version: "1.0.0", Locations: []types.Location{{StartLine: 578, EndLine: 581}}},
		{ID: "has@1.0.3", Name: "has", Version: "1.0.3", Locations: []types.Location{{StartLine: 583, EndLine: 588}}},
		{ID: "he@1.2.0", Name: "he", Version: "1.2.0", Locations: []types.Location{{StartLine: 590, EndLine: 593}}},
		{ID: "http-errors@1.6.3", Name: "http-errors", Version: "1.6.3", Locations: []types.Location{{StartLine: 595, EndLine: 603}}},
		{ID: "http-signature@1.2.0", Name: "http-signature", Version: "1.2.0", Locations: []types.Location{{StartLine: 605, EndLine: 612}}},
		{ID: "iconv-lite@0.4.23", Name: "iconv-lite", Version: "0.4.23", Locations: []types.Location{{StartLine: 614, EndLine: 619}}},
		{ID: "inflight@1.0.6", Name: "inflight", Version: "1.0.6", Locations: []types.Location{{StartLine: 621, EndLine: 627}}},
		{ID: "inherits@2.0.3", Name: "inherits", Version: "2.0.3", Locations: []types.Location{{StartLine: 629, EndLine: 632}}},
		{ID: "invert-kv@2.0.0", Name: "invert-kv", Version: "2.0.0", Locations: []types.Location{{StartLine: 634, EndLine: 637}}},
		{ID: "ipaddr.js@1.9.0", Name: "ipaddr.js", Version: "1.9.0", Locations: []types.Location{{StartLine: 639, EndLine: 642}}},
		{ID: "is-buffer@1.1.6", Name: "is-buffer", Version: "1.1.6", Locations: []types.Location{{StartLine: 644, EndLine: 647}}},
		{ID: "is-buffer@2.0.3", Name: "is-buffer", Version: "2.0.3", Locations: []types.Location{{StartLine: 649, EndLine: 652}}},
		{ID: "is-callable@1.1.4", Name: "is-callable", Version: "1.1.4", Locations: []types.Location{{StartLine: 654, EndLine: 657}}},
		{ID: "is-date-object@1.0.1", Name: "is-date-object", Version: "1.0.1", Locations: []types.Location{{StartLine: 659, EndLine: 662}}},
		{ID: "is-fullwidth-code-point@1.0.0", Name: "is-fullwidth-code-point", Version: "1.0.0", Locations: []types.Location{{StartLine: 664, EndLine: 669}}},
		{ID: "is-fullwidth-code-point@2.0.0", Name: "is-fullwidth-code-point", Version: "2.0.0", Locations: []types.Location{{StartLine: 671, EndLine: 674}}},
		{ID: "is-regex@1.0.4", Name: "is-regex", Version: "1.0.4", Locations: []types.Location{{StartLine: 676, EndLine: 681}}},
		{ID: "is-stream@1.1.0", Name: "is-stream", Version: "1.1.0", Locations: []types.Location{{StartLine: 683, EndLine: 686}}},
		{ID: "is-symbol@1.0.2", Name: "is-symbol", Version: "1.0.2", Locations: []types.Location{{StartLine: 688, EndLine: 693}}},
		{ID: "is-typedarray@1.0.0", Name: "is-typedarray", Version: "1.0.0", Locations: []types.Location{{StartLine: 695, EndLine: 698}}},
		{ID: "isexe@2.0.0", Name: "isexe", Version: "2.0.0", Locations: []types.Location{{StartLine: 700, EndLine: 703}}},
		{ID: "isstream@0.1.2", Name: "isstream", Version: "0.1.2", Locations: []types.Location{{StartLine: 705, EndLine: 708}}},
		{ID: "jquery@3.4.1", Name: "jquery", Version: "3.4.1", Locations: []types.Location{{StartLine: 710, EndLine: 713}}},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Locations: []types.Location{{StartLine: 715, EndLine: 718}}},
		{ID: "js-yaml@3.13.1", Name: "js-yaml", Version: "3.13.1", Locations: []types.Location{{StartLine: 720, EndLine: 726}}},
		{ID: "jsbn@0.1.1", Name: "jsbn", Version: "0.1.1", Locations: []types.Location{{StartLine: 728, EndLine: 731}}},
		{ID: "json-schema-traverse@0.4.1", Name: "json-schema-traverse", Version: "0.4.1", Locations: []types.Location{{StartLine: 733, EndLine: 736}}},
		{ID: "json-schema@0.2.3", Name: "json-schema", Version: "0.2.3", Locations: []types.Location{{StartLine: 738, EndLine: 741}}},
		{ID: "json-stringify-safe@5.0.1", Name: "json-stringify-safe", Version: "5.0.1", Locations: []types.Location{{StartLine: 743, EndLine: 746}}},
		{ID: "jsprim@1.4.1", Name: "jsprim", Version: "1.4.1", Locations: []types.Location{{StartLine: 748, EndLine: 756}}},
		{ID: "lcid@2.0.0", Name: "lcid", Version: "2.0.0", Locations: []types.Location{{StartLine: 758, EndLine: 763}}},
		{ID: "locate-path@3.0.0", Name: "locate-path", Version: "3.0.0", Locations: []types.Location{{StartLine: 765, EndLine: 771}}},
		{ID: "lodash@4.17.11", Name: "lodash", Version: "4.17.11", Locations: []types.Location{{StartLine: 773, EndLine: 776}}},
		{ID: "log-symbols@2.2.0", Name: "log-symbols", Version: "2.2.0", Locations: []types.Location{{StartLine: 778, EndLine: 783}}},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Locations: []types.Location{{StartLine: 785, EndLine: 790}}},
		{ID: "map-age-cleaner@0.1.3", Name: "map-age-cleaner", Version: "0.1.3", Locations: []types.Location{{StartLine: 792, EndLine: 797}}},
		{ID: "media-typer@0.3.0", Name: "media-typer", Version: "0.3.0", Locations: []types.Location{{StartLine: 799, EndLine: 802}}},
		{ID: "mem@4.3.0", Name: "mem", Version: "4.3.0", Locations: []types.Location{{StartLine: 804, EndLine: 811}}},
		{ID: "merge-descriptors@1.0.1", Name: "merge-descriptors", Version: "1.0.1", Locations: []types.Location{{StartLine: 813, EndLine: 816}}},
		{ID: "methods@1.1.2", Name: "methods", Version: "1.1.2", Locations: []types.Location{{StartLine: 818, EndLine: 821}}},
		{ID: "mime-db@1.40.0", Name: "mime-db", Version: "1.40.0", Locations: []types.Location{{StartLine: 823, EndLine: 826}}},
		{ID: "mime-types@2.1.24", Name: "mime-types", Version: "2.1.24", Locations: []types.Location{{StartLine: 828, EndLine: 833}}},
		{ID: "mime@1.4.1", Name: "mime", Version: "1.4.1", Locations: []types.Location{{StartLine: 835, EndLine: 838}}},
		{ID: "mimic-fn@2.1.0", Name: "mimic-fn", Version: "2.1.0", Locations: []types.Location{{StartLine: 840, EndLine: 843}}},
		{ID: "minimatch@3.0.4", Name: "minimatch", Version: "3.0.4", Locations: []types.Location{{StartLine: 845, EndLine: 850}}},
		{ID: "minimist@0.0.8", Name: "minimist", Version: "0.0.8", Locations: []types.Location{{StartLine: 852, EndLine: 855}}},
		{ID: "mkdirp@0.5.1", Name: "mkdirp", Version: "0.5.1", Locations: []types.Location{{StartLine: 857, EndLine: 862}}},
		{ID: "mocha@6.1.4", Name: "mocha", Version: "6.1.4", Locations: []types.Location{{StartLine: 864, EndLine: 891}}},
		{ID: "ms@2.0.0", Name: "ms", Version: "2.0.0", Locations: []types.Location{{StartLine: 893, EndLine: 896}}},
		{ID: "ms@2.1.1", Name: "ms", Version: "2.1.1", Locations: []types.Location{{StartLine: 898, EndLine: 901}}},
		{ID: "negotiator@0.6.2", Name: "negotiator", Version: "0.6.2", Locations: []types.Location{{StartLine: 903, EndLine: 906}}},
		{ID: "nice-try@1.0.5", Name: "nice-try", Version: "1.0.5", Locations: []types.Location{{StartLine: 908, EndLine: 911}}},
		{ID: "node-environment-flags@1.0.5", Name: "node-environment-flags", Version: "1.0.5", Locations: []types.Location{{StartLine: 913, EndLine: 919}}},
		{ID: "npm-run-path@2.0.2", Name: "npm-run-path", Version: "2.0.2", Locations: []types.Location{{StartLine: 921, EndLine: 926}}},
		{ID: "number-is-nan@1.0.1", Name: "number-is-nan", Version: "1.0.1", Locations: []types.Location{{StartLine: 928, EndLine: 931}}},
		{ID: "oauth-sign@0.9.0", Name: "oauth-sign", Version: "0.9.0", Locations: []types.Location{{StartLine: 933, EndLine: 936}}},
		{ID: "object-assign@4.1.1", Name: "object-assign", Version: "4.1.1", Locations: []types.Location{{StartLine: 938, EndLine: 941}}},
		{ID: "object-keys@1.1.1", Name: "object-keys", Version: "1.1.1", Locations: []types.Location{{StartLine: 943, EndLine: 946}}},
		{ID: "object.assign@4.1.0", Name: "object.assign", Version: "4.1.0", Locations: []types.Location{{StartLine: 948, EndLine: 956}}},
		{ID: "object.getownpropertydescriptors@2.0.3", Name: "object.getownpropertydescriptors", Version: "2.0.3", Locations: []types.Location{{StartLine: 958, EndLine: 964}}},
		{ID: "on-finished@2.3.0", Name: "on-finished", Version: "2.3.0", Locations: []types.Location{{StartLine: 966, EndLine: 971}}},
		{ID: "once@1.4.0", Name: "once", Version: "1.4.0", Locations: []types.Location{{StartLine: 973, EndLine: 978}}},
		{ID: "os-locale@3.1.0", Name: "os-locale", Version: "3.1.0", Locations: []types.Location{{StartLine: 980, EndLine: 987}}},
		{ID: "p-defer@1.0.0", Name: "p-defer", Version: "1.0.0", Locations: []types.Location{{StartLine: 989, EndLine: 992}}},
		{ID: "p-finally@1.0.0", Name: "p-finally", Version: "1.0.0", Locations: []types.Location{{StartLine: 994, EndLine: 997}}},
		{ID: "p-is-promise@2.1.0", Name: "p-is-promise", Version: "2.1.0", Locations: []types.Location{{StartLine: 999, EndLine: 1002}}},
		{ID: "p-limit@2.2.0", Name: "p-limit", Version: "2.2.0", Locations: []types.Location{{StartLine: 1004, EndLine: 1009}}},
		{ID: "p-locate@3.0.0", Name: "p-locate", Version: "3.0.0", Locations: []types.Location{{StartLine: 1011, EndLine: 1016}}},
		{ID: "p-try@2.2.0", Name: "p-try", Version: "2.2.0", Locations: []types.Location{{StartLine: 1018, EndLine: 1021}}},
		{ID: "parseurl@1.3.3", Name: "parseurl", Version: "1.3.3", Locations: []types.Location{{StartLine: 1023, EndLine: 1026}}},
		{ID: "path-exists@3.0.0", Name: "path-exists", Version: "3.0.0", Locations: []types.Location{{StartLine: 1028, EndLine: 1031}}},
		{ID: "path-is-absolute@1.0.1", Name: "path-is-absolute", Version: "1.0.1", Locations: []types.Location{{StartLine: 1033, EndLine: 1036}}},
		{ID: "path-key@2.0.1", Name: "path-key", Version: "2.0.1", Locations: []types.Location{{StartLine: 1038, EndLine: 1041}}},
		{ID: "path-to-regexp@0.1.7", Name: "path-to-regexp", Version: "0.1.7", Locations: []types.Location{{StartLine: 1043, EndLine: 1046}}},
		{ID: "performance-now@2.1.0", Name: "performance-now", Version: "2.1.0", Locations: []types.Location{{StartLine: 1048, EndLine: 1051}}},
		{ID: "promise@8.0.3", Name: "promise", Version: "8.0.3", Locations: []types.Location{{StartLine: 1053, EndLine: 1058}}},
		{ID: "prop-types@15.7.2", Name: "prop-types", Version: "15.7.2", Locations: []types.Location{{StartLine: 1060, EndLine: 1067}}},
		{ID: "proxy-addr@2.0.5", Name: "proxy-addr", Version: "2.0.5", Locations: []types.Location{{StartLine: 1069, EndLine: 1075}}},
		{ID: "psl@1.1.31", Name: "psl", Version: "1.1.31", Locations: []types.Location{{StartLine: 1077, EndLine: 1080}}},
		{ID: "pump@3.0.0", Name: "pump", Version: "3.0.0", Locations: []types.Location{{StartLine: 1082, EndLine: 1088}}},
		{ID: "punycode@1.4.1", Name: "punycode", Version: "1.4.1", Locations: []types.Location{{StartLine: 1090, EndLine: 1093}}},
		{ID: "punycode@2.1.1", Name: "punycode", Version: "2.1.1", Locations: []types.Location{{StartLine: 1095, EndLine: 1098}}},
		{ID: "qs@6.5.2", Name: "qs", Version: "6.5.2", Locations: []types.Location{{StartLine: 1100, EndLine: 1103}}},
		{ID: "range-parser@1.2.1", Name: "range-parser", Version: "1.2.1", Locations: []types.Location{{StartLine: 1105, EndLine: 1108}}},
		{ID: "raw-body@2.3.3", Name: "raw-body", Version: "2.3.3", Locations: []types.Location{{StartLine: 1110, EndLine: 1118}}},
		{ID: "react-is@16.8.6", Name: "react-is", Version: "16.8.6", Locations: []types.Location{{StartLine: 1120, EndLine: 1123}}},
		{ID: "react@16.8.6", Name: "react", Version: "16.8.6", Locations: []types.Location{{StartLine: 1125, EndLine: 1133}}},
		{ID: "redux@4.0.1", Name: "redux", Version: "4.0.1", Locations: []types.Location{{StartLine: 1135, EndLine: 1141}}},
		{ID: "request@2.88.0", Name: "request", Version: "2.88.0", Locations: []types.Location{{StartLine: 1143, EndLine: 1167}}},
		{ID: "require-directory@2.1.1", Name: "require-directory", Version: "2.1.1", Locations: []types.Location{{StartLine: 1169, EndLine: 1172}}},
		{ID: "require-main-filename@1.0.1", Name: "require-main-filename", Version: "1.0.1", Locations: []types.Location{{StartLine: 1174, EndLine: 1177}}},
		{ID: "require-main-filename@2.0.0", Name: "require-main-filename", Version: "2.0.0", Locations: []types.Location{{StartLine: 1179, EndLine: 1182}}},
		{ID: "safe-buffer@5.1.2", Name: "safe-buffer", Version: "5.1.2", Locations: []types.Location{{StartLine: 1184, EndLine: 1187}}},
		{ID: "safer-buffer@2.1.2", Name: "safer-buffer", Version: "2.1.2", Locations: []types.Location{{StartLine: 1189, EndLine: 1192}}},
		{ID: "scheduler@0.13.6", Name: "scheduler", Version: "0.13.6", Locations: []types.Location{{StartLine: 1194, EndLine: 1200}}},
		{ID: "semver@5.7.0", Name: "semver", Version: "5.7.0", Locations: []types.Location{{StartLine: 1202, EndLine: 1205}}},
		{ID: "send@0.16.2", Name: "send", Version: "0.16.2", Locations: []types.Location{{StartLine: 1207, EndLine: 1224}}},
		{ID: "serve-static@1.13.2", Name: "serve-static", Version: "1.13.2", Locations: []types.Location{{StartLine: 1226, EndLine: 1234}}},
		{ID: "set-blocking@2.0.0", Name: "set-blocking", Version: "2.0.0", Locations: []types.Location{{StartLine: 1236, EndLine: 1239}}},
		{ID: "setprototypeof@1.1.0", Name: "setprototypeof", Version: "1.1.0", Locations: []types.Location{{StartLine: 1241, EndLine: 1244}}},
		{ID: "shebang-command@1.2.0", Name: "shebang-command", Version: "1.2.0", Locations: []types.Location{{StartLine: 1246, EndLine: 1251}}},
		{ID: "shebang-regex@1.0.0", Name: "shebang-regex", Version: "1.0.0", Locations: []types.Location{{StartLine: 1253, EndLine: 1256}}},
		{ID: "signal-exit@3.0.2", Name: "signal-exit", Version: "3.0.2", Locations: []types.Location{{StartLine: 1258, EndLine: 1261}}},
		{ID: "sprintf-js@1.0.3", Name: "sprintf-js", Version: "1.0.3", Locations: []types.Location{{StartLine: 1263, EndLine: 1266}}},
		{ID: "sshpk@1.16.1", Name: "sshpk", Version: "1.16.1", Locations: []types.Location{{StartLine: 1268, EndLine: 1281}}},
		{ID: "statuses@1.5.0", Name: "statuses", Version: "1.5.0", Locations: []types.Location{{StartLine: 1283, EndLine: 1286}}},
		{ID: "statuses@1.4.0", Name: "statuses", Version: "1.4.0", Locations: []types.Location{{StartLine: 1288, EndLine: 1291}}},
		{ID: "string-width@1.0.2", Name: "string-width", Version: "1.0.2", Locations: []types.Location{{StartLine: 1293, EndLine: 1300}}},
		{ID: "string-width@2.1.1", Name: "string-width", Version: "2.1.1", Locations: []types.Location{{StartLine: 1302, EndLine: 1308}}},
		{ID: "string-width@3.1.0", Name: "string-width", Version: "3.1.0", Locations: []types.Location{{StartLine: 1310, EndLine: 1317}}},
		{ID: "strip-ansi@3.0.1", Name: "strip-ansi", Version: "3.0.1", Locations: []types.Location{{StartLine: 1319, EndLine: 1324}}},
		{ID: "strip-ansi@4.0.0", Name: "strip-ansi", Version: "4.0.0", Locations: []types.Location{{StartLine: 1326, EndLine: 1331}}},
		{ID: "strip-ansi@5.2.0", Name: "strip-ansi", Version: "5.2.0", Locations: []types.Location{{StartLine: 1333, EndLine: 1338}}},
		{ID: "strip-eof@1.0.0", Name: "strip-eof", Version: "1.0.0", Locations: []types.Location{{StartLine: 1340, EndLine: 1343}}},
		{ID: "strip-json-comments@2.0.1", Name: "strip-json-comments", Version: "2.0.1", Locations: []types.Location{{StartLine: 1345, EndLine: 1348}}},
		{ID: "supports-color@6.0.0", Name: "supports-color", Version: "6.0.0", Locations: []types.Location{{StartLine: 1350, EndLine: 1355}}},
		{ID: "supports-color@5.5.0", Name: "supports-color", Version: "5.5.0", Locations: []types.Location{{StartLine: 1357, EndLine: 1362}}},
		{ID: "symbol-observable@1.2.0", Name: "symbol-observable", Version: "1.2.0", Locations: []types.Location{{StartLine: 1364, EndLine: 1367}}},
		{ID: "tough-cookie@2.4.3", Name: "tough-cookie", Version: "2.4.3", Locations: []types.Location{{StartLine: 1369, EndLine: 1375}}},
		{ID: "tunnel-agent@0.6.0", Name: "tunnel-agent", Version: "0.6.0", Locations: []types.Location{{StartLine: 1377, EndLine: 1382}}},
		{ID: "tweetnacl@0.14.5", Name: "tweetnacl", Version: "0.14.5", Locations: []types.Location{{StartLine: 1384, EndLine: 1387}}},
		{ID: "type-is@1.6.18", Name: "type-is", Version: "1.6.18", Locations: []types.Location{{StartLine: 1389, EndLine: 1395}}},
		{ID: "unpipe@1.0.0", Name: "unpipe", Version: "1.0.0", Locations: []types.Location{{StartLine: 1397, EndLine: 1400}}},
		{ID: "uri-js@4.2.2", Name: "uri-js", Version: "4.2.2", Locations: []types.Location{{StartLine: 1402, EndLine: 1407}}},
		{ID: "utils-merge@1.0.1", Name: "utils-merge", Version: "1.0.1", Locations: []types.Location{{StartLine: 1409, EndLine: 1412}}},
		{ID: "uuid@3.3.2", Name: "uuid", Version: "3.3.2", Locations: []types.Location{{StartLine: 1414, EndLine: 1417}}},
		{ID: "vary@1.1.2", Name: "vary", Version: "1.1.2", Locations: []types.Location{{StartLine: 1419, EndLine: 1422}}},
		{ID: "verror@1.10.0", Name: "verror", Version: "1.10.0", Locations: []types.Location{{StartLine: 1424, EndLine: 1431}}},
		{ID: "vue@2.6.10", Name: "vue", Version: "2.6.10", Locations: []types.Location{{StartLine: 1433, EndLine: 1436}}},
		{ID: "which-module@2.0.0", Name: "which-module", Version: "2.0.0", Locations: []types.Location{{StartLine: 1438, EndLine: 1441}}},
		{ID: "which@1.3.1", Name: "which", Version: "1.3.1", Locations: []types.Location{{StartLine: 1443, EndLine: 1448}}},
		{ID: "wide-align@1.1.3", Name: "wide-align", Version: "1.1.3", Locations: []types.Location{{StartLine: 1450, EndLine: 1455}}},
		{ID: "wrap-ansi@2.1.0", Name: "wrap-ansi", Version: "2.1.0", Locations: []types.Location{{StartLine: 1457, EndLine: 1463}}},
		{ID: "wrappy@1.0.2", Name: "wrappy", Version: "1.0.2", Locations: []types.Location{{StartLine: 1465, EndLine: 1468}}},
		{ID: "y18n@4.0.0", Name: "y18n", Version: "4.0.0", Locations: []types.Location{{StartLine: 1470, EndLine: 1473}}},
		{ID: "yargs-parser@13.0.0", Name: "yargs-parser", Version: "13.0.0", Locations: []types.Location{{StartLine: 1475, EndLine: 1481}}},
		{ID: "yargs-parser@11.1.1", Name: "yargs-parser", Version: "11.1.1", Locations: []types.Location{{StartLine: 1483, EndLine: 1489}}},
		{ID: "yargs-parser@13.1.0", Name: "yargs-parser", Version: "13.1.0", Locations: []types.Location{{StartLine: 1491, EndLine: 1497}}},
		{ID: "yargs-unparser@1.5.0", Name: "yargs-unparser", Version: "1.5.0", Locations: []types.Location{{StartLine: 1499, EndLine: 1506}}},
		{ID: "yargs@13.2.2", Name: "yargs", Version: "13.2.2", Locations: []types.Location{{StartLine: 1508, EndLine: 1523}}},
		{ID: "yargs@12.0.5", Name: "yargs", Version: "12.0.5", Locations: []types.Location{{StartLine: 1525, EndLine: 1541}}},
	}

	// ... and
	// node test_deps_generator/index.js yarn.lock
	yarnManyDeps = []types.Dependency{
		{
			ID: "accepts@1.3.7",
			DependsOn: []string{
				"mime-types@2.1.24",
				"negotiator@0.6.2",
			},
		},
		{
			ID: "ajv@6.10.0",
			DependsOn: []string{
				"fast-deep-equal@2.0.1",
				"fast-json-stable-stringify@2.0.0",
				"json-schema-traverse@0.4.1",
				"uri-js@4.2.2",
			},
		},
		{
			ID: "ansi-styles@3.2.1",
			DependsOn: []string{
				"color-convert@1.9.3",
			},
		},
		{
			ID: "argparse@1.0.10",
			DependsOn: []string{
				"sprintf-js@1.0.3",
			},
		},
		{
			ID: "asn1@0.2.4",
			DependsOn: []string{
				"safer-buffer@2.1.2",
			},
		},
		{
			ID: "async@2.6.2",
			DependsOn: []string{
				"lodash@4.17.11",
			},
		},
		{
			ID: "axios@0.18.0",
			DependsOn: []string{
				"follow-redirects@1.7.0",
				"is-buffer@1.1.6",
			},
		},
		{
			ID: "bcrypt-pbkdf@1.0.2",
			DependsOn: []string{
				"tweetnacl@0.14.5",
			},
		},
		{
			ID: "body-parser@1.18.3",
			DependsOn: []string{
				"bytes@3.0.0",
				"content-type@1.0.4",
				"debug@2.6.9",
				"depd@1.1.2",
				"http-errors@1.6.3",
				"iconv-lite@0.4.23",
				"on-finished@2.3.0",
				"qs@6.5.2",
				"raw-body@2.3.3",
				"type-is@1.6.18",
			},
		},
		{
			ID: "brace-expansion@1.1.11",
			DependsOn: []string{
				"balanced-match@1.0.0",
				"concat-map@0.0.1",
			},
		},
		{
			ID: "chalk@2.4.2",
			DependsOn: []string{
				"ansi-styles@3.2.1",
				"escape-string-regexp@1.0.5",
				"supports-color@5.5.0",
			},
		},
		{
			ID: "cliui@4.1.0",
			DependsOn: []string{
				"string-width@2.1.1",
				"strip-ansi@4.0.0",
				"wrap-ansi@2.1.0",
			},
		},
		{
			ID: "color-convert@1.9.3",
			DependsOn: []string{
				"color-name@1.1.3",
			},
		},
		{
			ID: "combined-stream@1.0.8",
			DependsOn: []string{
				"delayed-stream@1.0.0",
			},
		},
		{
			ID: "cross-spawn@6.0.5",
			DependsOn: []string{
				"nice-try@1.0.5",
				"path-key@2.0.1",
				"semver@5.7.0",
				"shebang-command@1.2.0",
				"which@1.3.1",
			},
		},
		{
			ID: "dashdash@1.14.1",
			DependsOn: []string{
				"assert-plus@1.0.0",
			},
		},
		{
			ID: "debug@2.6.9",
			DependsOn: []string{
				"ms@2.0.0",
			},
		},
		{
			ID: "debug@3.2.6",
			DependsOn: []string{
				"ms@2.1.1",
			},
		},
		{
			ID: "define-properties@1.1.3",
			DependsOn: []string{
				"object-keys@1.1.1",
			},
		},
		{
			ID: "ecc-jsbn@0.1.2",
			DependsOn: []string{
				"jsbn@0.1.1",
				"safer-buffer@2.1.2",
			},
		},
		{
			ID: "end-of-stream@1.4.1",
			DependsOn: []string{
				"once@1.4.0",
			},
		},
		{
			ID: "es-abstract@1.13.0",
			DependsOn: []string{
				"es-to-primitive@1.2.0",
				"function-bind@1.1.1",
				"has@1.0.3",
				"is-callable@1.1.4",
				"is-regex@1.0.4",
				"object-keys@1.1.1",
			},
		},
		{
			ID: "es-to-primitive@1.2.0",
			DependsOn: []string{
				"is-callable@1.1.4",
				"is-date-object@1.0.1",
				"is-symbol@1.0.2",
			},
		},
		{
			ID: "execa@1.0.0",
			DependsOn: []string{
				"cross-spawn@6.0.5",
				"get-stream@4.1.0",
				"is-stream@1.1.0",
				"npm-run-path@2.0.2",
				"p-finally@1.0.0",
				"signal-exit@3.0.2",
				"strip-eof@1.0.0",
			},
		},
		{
			ID: "express@4.16.4",
			DependsOn: []string{
				"accepts@1.3.7",
				"array-flatten@1.1.1",
				"body-parser@1.18.3",
				"content-disposition@0.5.2",
				"content-type@1.0.4",
				"cookie@0.3.1",
				"cookie-signature@1.0.6",
				"debug@2.6.9",
				"depd@1.1.2",
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"etag@1.8.1",
				"finalhandler@1.1.1",
				"fresh@0.5.2",
				"merge-descriptors@1.0.1",
				"methods@1.1.2",
				"on-finished@2.3.0",
				"parseurl@1.3.3",
				"path-to-regexp@0.1.7",
				"proxy-addr@2.0.5",
				"qs@6.5.2",
				"range-parser@1.2.1",
				"safe-buffer@5.1.2",
				"send@0.16.2",
				"serve-static@1.13.2",
				"setprototypeof@1.1.0",
				"statuses@1.4.0",
				"type-is@1.6.18",
				"utils-merge@1.0.1",
				"vary@1.1.2",
			},
		},
		{
			ID: "finalhandler@1.1.1",
			DependsOn: []string{
				"debug@2.6.9",
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"on-finished@2.3.0",
				"parseurl@1.3.3",
				"statuses@1.4.0",
				"unpipe@1.0.0",
			},
		},
		{
			ID: "find-up@3.0.0",
			DependsOn: []string{
				"locate-path@3.0.0",
			},
		},
		{
			ID: "flat@4.1.0",
			DependsOn: []string{
				"is-buffer@2.0.3",
			},
		},
		{
			ID: "follow-redirects@1.7.0",
			DependsOn: []string{
				"debug@3.2.6",
			},
		},
		{
			ID: "form-data@2.3.3",
			DependsOn: []string{
				"asynckit@0.4.0",
				"combined-stream@1.0.8",
				"mime-types@2.1.24",
			},
		},
		{
			ID: "get-stream@4.1.0",
			DependsOn: []string{
				"pump@3.0.0",
			},
		},
		{
			ID: "getpass@0.1.7",
			DependsOn: []string{
				"assert-plus@1.0.0",
			},
		},
		{
			ID: "glob@7.1.3",
			DependsOn: []string{
				"fs.realpath@1.0.0",
				"inflight@1.0.6",
				"inherits@2.0.3",
				"minimatch@3.0.4",
				"once@1.4.0",
				"path-is-absolute@1.0.1",
			},
		},
		{
			ID: "har-validator@5.1.3",
			DependsOn: []string{
				"ajv@6.10.0",
				"har-schema@2.0.0",
			},
		},
		{
			ID: "has@1.0.3",
			DependsOn: []string{
				"function-bind@1.1.1",
			},
		},
		{
			ID: "http-errors@1.6.3",
			DependsOn: []string{
				"depd@1.1.2",
				"inherits@2.0.3",
				"setprototypeof@1.1.0",
				"statuses@1.5.0",
			},
		},
		{
			ID: "http-signature@1.2.0",
			DependsOn: []string{
				"assert-plus@1.0.0",
				"jsprim@1.4.1",
				"sshpk@1.16.1",
			},
		},
		{
			ID: "iconv-lite@0.4.23",
			DependsOn: []string{
				"safer-buffer@2.1.2",
			},
		},
		{
			ID: "inflight@1.0.6",
			DependsOn: []string{
				"once@1.4.0",
				"wrappy@1.0.2",
			},
		},
		{
			ID: "is-fullwidth-code-point@1.0.0",
			DependsOn: []string{
				"number-is-nan@1.0.1",
			},
		},
		{
			ID: "is-regex@1.0.4",
			DependsOn: []string{
				"has@1.0.3",
			},
		},
		{
			ID: "is-symbol@1.0.2",
			DependsOn: []string{
				"has-symbols@1.0.0",
			},
		},
		{
			ID: "js-yaml@3.13.1",
			DependsOn: []string{
				"argparse@1.0.10",
				"esprima@4.0.1",
			},
		},
		{
			ID: "jsprim@1.4.1",
			DependsOn: []string{
				"assert-plus@1.0.0",
				"extsprintf@1.3.0",
				"json-schema@0.2.3",
				"verror@1.10.0",
			},
		},
		{
			ID: "lcid@2.0.0",
			DependsOn: []string{
				"invert-kv@2.0.0",
			},
		},
		{
			ID: "locate-path@3.0.0",
			DependsOn: []string{
				"p-locate@3.0.0",
				"path-exists@3.0.0",
			},
		},
		{
			ID: "log-symbols@2.2.0",
			DependsOn: []string{
				"chalk@2.4.2",
			},
		},
		{
			ID: "loose-envify@1.4.0",
			DependsOn: []string{
				"js-tokens@4.0.0",
			},
		},
		{
			ID: "map-age-cleaner@0.1.3",
			DependsOn: []string{
				"p-defer@1.0.0",
			},
		},
		{
			ID: "mem@4.3.0",
			DependsOn: []string{
				"map-age-cleaner@0.1.3",
				"mimic-fn@2.1.0",
				"p-is-promise@2.1.0",
			},
		},
		{
			ID: "mime-types@2.1.24",
			DependsOn: []string{
				"mime-db@1.40.0",
			},
		},
		{
			ID: "minimatch@3.0.4",
			DependsOn: []string{
				"brace-expansion@1.1.11",
			},
		},
		{
			ID: "mkdirp@0.5.1",
			DependsOn: []string{
				"minimist@0.0.8",
			},
		},
		{
			ID: "mocha@6.1.4",
			DependsOn: []string{
				"ansi-colors@3.2.3",
				"browser-stdout@1.3.1",
				"debug@3.2.6",
				"diff@3.5.0",
				"escape-string-regexp@1.0.5",
				"find-up@3.0.0",
				"glob@7.1.3",
				"growl@1.10.5",
				"he@1.2.0",
				"js-yaml@3.13.1",
				"log-symbols@2.2.0",
				"minimatch@3.0.4",
				"mkdirp@0.5.1",
				"ms@2.1.1",
				"node-environment-flags@1.0.5",
				"object.assign@4.1.0",
				"strip-json-comments@2.0.1",
				"supports-color@6.0.0",
				"which@1.3.1",
				"wide-align@1.1.3",
				"yargs@13.2.2",
				"yargs-parser@13.0.0",
				"yargs-unparser@1.5.0",
			},
		},
		{
			ID: "node-environment-flags@1.0.5",
			DependsOn: []string{
				"object.getownpropertydescriptors@2.0.3",
				"semver@5.7.0",
			},
		},
		{
			ID: "npm-run-path@2.0.2",
			DependsOn: []string{
				"path-key@2.0.1",
			},
		},
		{
			ID: "object.assign@4.1.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"function-bind@1.1.1",
				"has-symbols@1.0.0",
				"object-keys@1.1.1",
			},
		},
		{
			ID: "object.getownpropertydescriptors@2.0.3",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
			},
		},
		{
			ID: "on-finished@2.3.0",
			DependsOn: []string{
				"ee-first@1.1.1",
			},
		},
		{
			ID: "once@1.4.0",
			DependsOn: []string{
				"wrappy@1.0.2",
			},
		},
		{
			ID: "os-locale@3.1.0",
			DependsOn: []string{
				"execa@1.0.0",
				"lcid@2.0.0",
				"mem@4.3.0",
			},
		},
		{
			ID: "p-limit@2.2.0",
			DependsOn: []string{
				"p-try@2.2.0",
			},
		},
		{
			ID: "p-locate@3.0.0",
			DependsOn: []string{
				"p-limit@2.2.0",
			},
		},
		{
			ID: "promise@8.0.3",
			DependsOn: []string{
				"asap@2.0.6",
			},
		},
		{
			ID: "prop-types@15.7.2",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"react-is@16.8.6",
			},
		},
		{
			ID: "proxy-addr@2.0.5",
			DependsOn: []string{
				"forwarded@0.1.2",
				"ipaddr.js@1.9.0",
			},
		},
		{
			ID: "pump@3.0.0",
			DependsOn: []string{
				"end-of-stream@1.4.1",
				"once@1.4.0",
			},
		},
		{
			ID: "raw-body@2.3.3",
			DependsOn: []string{
				"bytes@3.0.0",
				"http-errors@1.6.3",
				"iconv-lite@0.4.23",
				"unpipe@1.0.0",
			},
		},
		{
			ID: "react@16.8.6",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"prop-types@15.7.2",
				"scheduler@0.13.6",
			},
		},
		{
			ID: "redux@4.0.1",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"symbol-observable@1.2.0",
			},
		},
		{
			ID: "request@2.88.0",
			DependsOn: []string{
				"aws-sign2@0.7.0",
				"aws4@1.8.0",
				"caseless@0.12.0",
				"combined-stream@1.0.8",
				"extend@3.0.2",
				"forever-agent@0.6.1",
				"form-data@2.3.3",
				"har-validator@5.1.3",
				"http-signature@1.2.0",
				"is-typedarray@1.0.0",
				"isstream@0.1.2",
				"json-stringify-safe@5.0.1",
				"mime-types@2.1.24",
				"oauth-sign@0.9.0",
				"performance-now@2.1.0",
				"qs@6.5.2",
				"safe-buffer@5.1.2",
				"tough-cookie@2.4.3",
				"tunnel-agent@0.6.0",
				"uuid@3.3.2",
			},
		},
		{
			ID: "scheduler@0.13.6",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
			},
		},
		{
			ID: "send@0.16.2",
			DependsOn: []string{
				"debug@2.6.9",
				"depd@1.1.2",
				"destroy@1.0.4",
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"etag@1.8.1",
				"fresh@0.5.2",
				"http-errors@1.6.3",
				"mime@1.4.1",
				"ms@2.0.0",
				"on-finished@2.3.0",
				"range-parser@1.2.1",
				"statuses@1.4.0",
			},
		},
		{
			ID: "serve-static@1.13.2",
			DependsOn: []string{
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"parseurl@1.3.3",
				"send@0.16.2",
			},
		},
		{
			ID: "shebang-command@1.2.0",
			DependsOn: []string{
				"shebang-regex@1.0.0",
			},
		},
		{
			ID: "sshpk@1.16.1",
			DependsOn: []string{
				"asn1@0.2.4",
				"assert-plus@1.0.0",
				"bcrypt-pbkdf@1.0.2",
				"dashdash@1.14.1",
				"ecc-jsbn@0.1.2",
				"getpass@0.1.7",
				"jsbn@0.1.1",
				"safer-buffer@2.1.2",
				"tweetnacl@0.14.5",
			},
		},
		{
			ID: "string-width@1.0.2",
			DependsOn: []string{
				"code-point-at@1.1.0",
				"is-fullwidth-code-point@1.0.0",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID: "string-width@2.1.1",
			DependsOn: []string{
				"is-fullwidth-code-point@2.0.0",
				"strip-ansi@4.0.0",
			},
		},
		{
			ID: "string-width@3.1.0",
			DependsOn: []string{
				"emoji-regex@7.0.3",
				"is-fullwidth-code-point@2.0.0",
				"strip-ansi@5.2.0",
			},
		},
		{
			ID: "strip-ansi@3.0.1",
			DependsOn: []string{
				"ansi-regex@2.1.1",
			},
		},
		{
			ID: "strip-ansi@4.0.0",
			DependsOn: []string{
				"ansi-regex@3.0.0",
			},
		},
		{
			ID: "strip-ansi@5.2.0",
			DependsOn: []string{
				"ansi-regex@4.1.0",
			},
		},
		{
			ID: "supports-color@6.0.0",
			DependsOn: []string{
				"has-flag@3.0.0",
			},
		},
		{
			ID: "supports-color@5.5.0",
			DependsOn: []string{
				"has-flag@3.0.0",
			},
		},
		{
			ID: "tough-cookie@2.4.3",
			DependsOn: []string{
				"psl@1.1.31",
				"punycode@1.4.1",
			},
		},
		{
			ID: "tunnel-agent@0.6.0",
			DependsOn: []string{
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "type-is@1.6.18",
			DependsOn: []string{
				"media-typer@0.3.0",
				"mime-types@2.1.24",
			},
		},
		{
			ID: "uri-js@4.2.2",
			DependsOn: []string{
				"punycode@2.1.1",
			},
		},
		{
			ID: "verror@1.10.0",
			DependsOn: []string{
				"assert-plus@1.0.0",
				"core-util-is@1.0.2",
				"extsprintf@1.4.0",
			},
		},
		{
			ID: "which@1.3.1",
			DependsOn: []string{
				"isexe@2.0.0",
			},
		},
		{
			ID: "wide-align@1.1.3",
			DependsOn: []string{
				"string-width@2.1.1",
			},
		},
		{
			ID: "wrap-ansi@2.1.0",
			DependsOn: []string{
				"string-width@1.0.2",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID: "yargs-parser@13.0.0",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
			},
		},
		{
			ID: "yargs-parser@11.1.1",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
			},
		},
		{
			ID: "yargs-parser@13.1.0",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
			},
		},
		{
			ID: "yargs-unparser@1.5.0",
			DependsOn: []string{
				"flat@4.1.0",
				"lodash@4.17.11",
				"yargs@12.0.5",
			},
		},
		{
			ID: "yargs@13.2.2",
			DependsOn: []string{
				"cliui@4.1.0",
				"find-up@3.0.0",
				"get-caller-file@2.0.5",
				"os-locale@3.1.0",
				"require-directory@2.1.1",
				"require-main-filename@2.0.0",
				"set-blocking@2.0.0",
				"string-width@3.1.0",
				"which-module@2.0.0",
				"y18n@4.0.0",
				"yargs-parser@13.1.0",
			},
		},
		{
			ID: "yargs@12.0.5",
			DependsOn: []string{
				"cliui@4.1.0",
				"decamelize@1.2.0",
				"find-up@3.0.0",
				"get-caller-file@1.0.3",
				"os-locale@3.1.0",
				"require-directory@2.1.1",
				"require-main-filename@1.0.1",
				"set-blocking@2.0.0",
				"string-width@2.1.1",
				"which-module@2.0.0",
				"y18n@4.0.0",
				"yargs-parser@11.1.1",
			},
		},
	}

	// yarn list | grep -E -o "\S+@[^\^~]\S+" | awk -F@ 'NR>0 {printf("{\""$1"\", \""$2"\", \"\"},\n")}' | sort | uniq
	// to get deps with locations from lock file use following commands:
	// awk '/^\S+@[~^*]?(>= )?[0-9.]*/,/^$/{if($0=="") {print "--"prev} else { if(substr($0,1,2)!="  ") {print NR":"$0} else {print $0}} prev=NR}; END{print "--"prev}' | awk 'BEGIN {s=""}; {(substr($0,1,2)=="--") ? (s=s$0"\n") : (s=s$0)}; END { print s}' | sed -E 's/@([0-9~><*\^]|npm).*version:? "?/:/' | sed 's/  /:/' | sed 's/"//g'| awk 'match($0, /[[:digit:]]+$/) {print substr($0, RSTART, RLENGTH)":"$0 }' |  awk -F":" '{print "{ID: \""$3"@"$4"\", Name: \""$3"\", Version: \""$4"\", Locations: []types.Location{{StartLine: "$2", EndLine: "$1"}}},"}'
	yarnRealWorld = []types.Library{
		{ID: "@babel/code-frame@7.0.0", Name: "@babel/code-frame", Version: "7.0.0", Locations: []types.Location{{StartLine: 5, EndLine: 10}}},
		{ID: "@babel/code-frame@7.0.0-beta.44", Name: "@babel/code-frame", Version: "7.0.0-beta.44", Locations: []types.Location{{StartLine: 12, EndLine: 17}}},
		{ID: "@babel/core@7.1.0", Name: "@babel/core", Version: "7.1.0", Locations: []types.Location{{StartLine: 19, EndLine: 37}}},
		{ID: "@babel/core@7.4.4", Name: "@babel/core", Version: "7.4.4", Locations: []types.Location{{StartLine: 39, EndLine: 57}}},
		{ID: "@babel/generator@7.0.0-beta.44", Name: "@babel/generator", Version: "7.0.0-beta.44", Locations: []types.Location{{StartLine: 59, EndLine: 68}}},
		{ID: "@babel/generator@7.4.4", Name: "@babel/generator", Version: "7.4.4", Locations: []types.Location{{StartLine: 70, EndLine: 79}}},
		{ID: "@babel/helper-annotate-as-pure@7.0.0", Name: "@babel/helper-annotate-as-pure", Version: "7.0.0", Locations: []types.Location{{StartLine: 81, EndLine: 86}}},
		{ID: "@babel/helper-builder-binary-assignment-operator-visitor@7.1.0", Name: "@babel/helper-builder-binary-assignment-operator-visitor", Version: "7.1.0", Locations: []types.Location{{StartLine: 88, EndLine: 94}}},
		{ID: "@babel/helper-builder-react-jsx@7.3.0", Name: "@babel/helper-builder-react-jsx", Version: "7.3.0", Locations: []types.Location{{StartLine: 96, EndLine: 102}}},
		{ID: "@babel/helper-call-delegate@7.4.4", Name: "@babel/helper-call-delegate", Version: "7.4.4", Locations: []types.Location{{StartLine: 104, EndLine: 111}}},
		{ID: "@babel/helper-create-class-features-plugin@7.4.4", Name: "@babel/helper-create-class-features-plugin", Version: "7.4.4", Locations: []types.Location{{StartLine: 113, EndLine: 123}}},
		{ID: "@babel/helper-define-map@7.4.4", Name: "@babel/helper-define-map", Version: "7.4.4", Locations: []types.Location{{StartLine: 125, EndLine: 132}}},
		{ID: "@babel/helper-explode-assignable-expression@7.1.0", Name: "@babel/helper-explode-assignable-expression", Version: "7.1.0", Locations: []types.Location{{StartLine: 134, EndLine: 140}}},
		{ID: "@babel/helper-function-name@7.0.0-beta.44", Name: "@babel/helper-function-name", Version: "7.0.0-beta.44", Locations: []types.Location{{StartLine: 142, EndLine: 149}}},
		{ID: "@babel/helper-function-name@7.1.0", Name: "@babel/helper-function-name", Version: "7.1.0", Locations: []types.Location{{StartLine: 151, EndLine: 158}}},
		{ID: "@babel/helper-get-function-arity@7.0.0-beta.44", Name: "@babel/helper-get-function-arity", Version: "7.0.0-beta.44", Locations: []types.Location{{StartLine: 160, EndLine: 165}}},
		{ID: "@babel/helper-get-function-arity@7.0.0", Name: "@babel/helper-get-function-arity", Version: "7.0.0", Locations: []types.Location{{StartLine: 167, EndLine: 172}}},
		{ID: "@babel/helper-hoist-variables@7.4.4", Name: "@babel/helper-hoist-variables", Version: "7.4.4", Locations: []types.Location{{StartLine: 174, EndLine: 179}}},
		{ID: "@babel/helper-member-expression-to-functions@7.0.0", Name: "@babel/helper-member-expression-to-functions", Version: "7.0.0", Locations: []types.Location{{StartLine: 181, EndLine: 186}}},
		{ID: "@babel/helper-module-imports@7.0.0", Name: "@babel/helper-module-imports", Version: "7.0.0", Locations: []types.Location{{StartLine: 188, EndLine: 193}}},
		{ID: "@babel/helper-module-transforms@7.4.4", Name: "@babel/helper-module-transforms", Version: "7.4.4", Locations: []types.Location{{StartLine: 195, EndLine: 205}}},
		{ID: "@babel/helper-optimise-call-expression@7.0.0", Name: "@babel/helper-optimise-call-expression", Version: "7.0.0", Locations: []types.Location{{StartLine: 207, EndLine: 212}}},
		{ID: "@babel/helper-plugin-utils@7.0.0", Name: "@babel/helper-plugin-utils", Version: "7.0.0", Locations: []types.Location{{StartLine: 214, EndLine: 217}}},
		{ID: "@babel/helper-regex@7.4.4", Name: "@babel/helper-regex", Version: "7.4.4", Locations: []types.Location{{StartLine: 219, EndLine: 224}}},
		{ID: "@babel/helper-remap-async-to-generator@7.1.0", Name: "@babel/helper-remap-async-to-generator", Version: "7.1.0", Locations: []types.Location{{StartLine: 226, EndLine: 235}}},
		{ID: "@babel/helper-replace-supers@7.4.4", Name: "@babel/helper-replace-supers", Version: "7.4.4", Locations: []types.Location{{StartLine: 237, EndLine: 245}}},
		{ID: "@babel/helper-simple-access@7.1.0", Name: "@babel/helper-simple-access", Version: "7.1.0", Locations: []types.Location{{StartLine: 247, EndLine: 253}}},
		{ID: "@babel/helper-split-export-declaration@7.0.0-beta.44", Name: "@babel/helper-split-export-declaration", Version: "7.0.0-beta.44", Locations: []types.Location{{StartLine: 255, EndLine: 260}}},
		{ID: "@babel/helper-split-export-declaration@7.4.4", Name: "@babel/helper-split-export-declaration", Version: "7.4.4", Locations: []types.Location{{StartLine: 262, EndLine: 267}}},
		{ID: "@babel/helper-wrap-function@7.2.0", Name: "@babel/helper-wrap-function", Version: "7.2.0", Locations: []types.Location{{StartLine: 269, EndLine: 277}}},
		{ID: "@babel/helpers@7.4.4", Name: "@babel/helpers", Version: "7.4.4", Locations: []types.Location{{StartLine: 279, EndLine: 286}}},
		{ID: "@babel/highlight@7.0.0-beta.44", Name: "@babel/highlight", Version: "7.0.0-beta.44", Locations: []types.Location{{StartLine: 288, EndLine: 295}}},
		{ID: "@babel/highlight@7.0.0", Name: "@babel/highlight", Version: "7.0.0", Locations: []types.Location{{StartLine: 297, EndLine: 304}}},
		{ID: "@babel/parser@7.4.4", Name: "@babel/parser", Version: "7.4.4", Locations: []types.Location{{StartLine: 306, EndLine: 309}}},
		{ID: "@babel/plugin-proposal-async-generator-functions@7.2.0", Name: "@babel/plugin-proposal-async-generator-functions", Version: "7.2.0", Locations: []types.Location{{StartLine: 311, EndLine: 318}}},
		{ID: "@babel/plugin-proposal-class-properties@7.1.0", Name: "@babel/plugin-proposal-class-properties", Version: "7.1.0", Locations: []types.Location{{StartLine: 320, EndLine: 330}}},
		{ID: "@babel/plugin-proposal-class-properties@7.4.4", Name: "@babel/plugin-proposal-class-properties", Version: "7.4.4", Locations: []types.Location{{StartLine: 332, EndLine: 338}}},
		{ID: "@babel/plugin-proposal-decorators@7.1.2", Name: "@babel/plugin-proposal-decorators", Version: "7.1.2", Locations: []types.Location{{StartLine: 340, EndLine: 348}}},
		{ID: "@babel/plugin-proposal-json-strings@7.2.0", Name: "@babel/plugin-proposal-json-strings", Version: "7.2.0", Locations: []types.Location{{StartLine: 350, EndLine: 356}}},
		{ID: "@babel/plugin-proposal-object-rest-spread@7.0.0", Name: "@babel/plugin-proposal-object-rest-spread", Version: "7.0.0", Locations: []types.Location{{StartLine: 358, EndLine: 364}}},
		{ID: "@babel/plugin-proposal-object-rest-spread@7.4.4", Name: "@babel/plugin-proposal-object-rest-spread", Version: "7.4.4", Locations: []types.Location{{StartLine: 366, EndLine: 372}}},
		{ID: "@babel/plugin-proposal-optional-catch-binding@7.2.0", Name: "@babel/plugin-proposal-optional-catch-binding", Version: "7.2.0", Locations: []types.Location{{StartLine: 374, EndLine: 380}}},
		{ID: "@babel/plugin-proposal-unicode-property-regex@7.4.4", Name: "@babel/plugin-proposal-unicode-property-regex", Version: "7.4.4", Locations: []types.Location{{StartLine: 382, EndLine: 389}}},
		{ID: "@babel/plugin-syntax-async-generators@7.2.0", Name: "@babel/plugin-syntax-async-generators", Version: "7.2.0", Locations: []types.Location{{StartLine: 391, EndLine: 396}}},
		{ID: "@babel/plugin-syntax-class-properties@7.2.0", Name: "@babel/plugin-syntax-class-properties", Version: "7.2.0", Locations: []types.Location{{StartLine: 398, EndLine: 403}}},
		{ID: "@babel/plugin-syntax-decorators@7.2.0", Name: "@babel/plugin-syntax-decorators", Version: "7.2.0", Locations: []types.Location{{StartLine: 405, EndLine: 410}}},
		{ID: "@babel/plugin-syntax-dynamic-import@7.0.0", Name: "@babel/plugin-syntax-dynamic-import", Version: "7.0.0", Locations: []types.Location{{StartLine: 412, EndLine: 417}}},
		{ID: "@babel/plugin-syntax-dynamic-import@7.2.0", Name: "@babel/plugin-syntax-dynamic-import", Version: "7.2.0", Locations: []types.Location{{StartLine: 419, EndLine: 424}}},
		{ID: "@babel/plugin-syntax-flow@7.2.0", Name: "@babel/plugin-syntax-flow", Version: "7.2.0", Locations: []types.Location{{StartLine: 426, EndLine: 431}}},
		{ID: "@babel/plugin-syntax-json-strings@7.2.0", Name: "@babel/plugin-syntax-json-strings", Version: "7.2.0", Locations: []types.Location{{StartLine: 433, EndLine: 438}}},
		{ID: "@babel/plugin-syntax-jsx@7.2.0", Name: "@babel/plugin-syntax-jsx", Version: "7.2.0", Locations: []types.Location{{StartLine: 440, EndLine: 445}}},
		{ID: "@babel/plugin-syntax-object-rest-spread@7.2.0", Name: "@babel/plugin-syntax-object-rest-spread", Version: "7.2.0", Locations: []types.Location{{StartLine: 447, EndLine: 452}}},
		{ID: "@babel/plugin-syntax-optional-catch-binding@7.2.0", Name: "@babel/plugin-syntax-optional-catch-binding", Version: "7.2.0", Locations: []types.Location{{StartLine: 454, EndLine: 459}}},
		{ID: "@babel/plugin-syntax-typescript@7.3.3", Name: "@babel/plugin-syntax-typescript", Version: "7.3.3", Locations: []types.Location{{StartLine: 461, EndLine: 466}}},
		{ID: "@babel/plugin-transform-arrow-functions@7.2.0", Name: "@babel/plugin-transform-arrow-functions", Version: "7.2.0", Locations: []types.Location{{StartLine: 468, EndLine: 473}}},
		{ID: "@babel/plugin-transform-async-to-generator@7.4.4", Name: "@babel/plugin-transform-async-to-generator", Version: "7.4.4", Locations: []types.Location{{StartLine: 475, EndLine: 482}}},
		{ID: "@babel/plugin-transform-block-scoped-functions@7.2.0", Name: "@babel/plugin-transform-block-scoped-functions", Version: "7.2.0", Locations: []types.Location{{StartLine: 484, EndLine: 489}}},
		{ID: "@babel/plugin-transform-block-scoping@7.4.4", Name: "@babel/plugin-transform-block-scoping", Version: "7.4.4", Locations: []types.Location{{StartLine: 491, EndLine: 497}}},
		{ID: "@babel/plugin-transform-classes@7.1.0", Name: "@babel/plugin-transform-classes", Version: "7.1.0", Locations: []types.Location{{StartLine: 499, EndLine: 511}}},
		{ID: "@babel/plugin-transform-classes@7.4.4", Name: "@babel/plugin-transform-classes", Version: "7.4.4", Locations: []types.Location{{StartLine: 513, EndLine: 525}}},
		{ID: "@babel/plugin-transform-computed-properties@7.2.0", Name: "@babel/plugin-transform-computed-properties", Version: "7.2.0", Locations: []types.Location{{StartLine: 527, EndLine: 532}}},
		{ID: "@babel/plugin-transform-destructuring@7.0.0", Name: "@babel/plugin-transform-destructuring", Version: "7.0.0", Locations: []types.Location{{StartLine: 534, EndLine: 539}}},
		{ID: "@babel/plugin-transform-destructuring@7.4.4", Name: "@babel/plugin-transform-destructuring", Version: "7.4.4", Locations: []types.Location{{StartLine: 541, EndLine: 546}}},
		{ID: "@babel/plugin-transform-dotall-regex@7.4.4", Name: "@babel/plugin-transform-dotall-regex", Version: "7.4.4", Locations: []types.Location{{StartLine: 548, EndLine: 555}}},
		{ID: "@babel/plugin-transform-duplicate-keys@7.2.0", Name: "@babel/plugin-transform-duplicate-keys", Version: "7.2.0", Locations: []types.Location{{StartLine: 557, EndLine: 562}}},
		{ID: "@babel/plugin-transform-exponentiation-operator@7.2.0", Name: "@babel/plugin-transform-exponentiation-operator", Version: "7.2.0", Locations: []types.Location{{StartLine: 564, EndLine: 570}}},
		{ID: "@babel/plugin-transform-flow-strip-types@7.0.0", Name: "@babel/plugin-transform-flow-strip-types", Version: "7.0.0", Locations: []types.Location{{StartLine: 572, EndLine: 578}}},
		{ID: "@babel/plugin-transform-flow-strip-types@7.4.4", Name: "@babel/plugin-transform-flow-strip-types", Version: "7.4.4", Locations: []types.Location{{StartLine: 580, EndLine: 586}}},
		{ID: "@babel/plugin-transform-for-of@7.4.4", Name: "@babel/plugin-transform-for-of", Version: "7.4.4", Locations: []types.Location{{StartLine: 588, EndLine: 593}}},
		{ID: "@babel/plugin-transform-function-name@7.4.4", Name: "@babel/plugin-transform-function-name", Version: "7.4.4", Locations: []types.Location{{StartLine: 595, EndLine: 601}}},
		{ID: "@babel/plugin-transform-literals@7.2.0", Name: "@babel/plugin-transform-literals", Version: "7.2.0", Locations: []types.Location{{StartLine: 603, EndLine: 608}}},
		{ID: "@babel/plugin-transform-member-expression-literals@7.2.0", Name: "@babel/plugin-transform-member-expression-literals", Version: "7.2.0", Locations: []types.Location{{StartLine: 610, EndLine: 615}}},
		{ID: "@babel/plugin-transform-modules-amd@7.2.0", Name: "@babel/plugin-transform-modules-amd", Version: "7.2.0", Locations: []types.Location{{StartLine: 617, EndLine: 623}}},
		{ID: "@babel/plugin-transform-modules-commonjs@7.4.4", Name: "@babel/plugin-transform-modules-commonjs", Version: "7.4.4", Locations: []types.Location{{StartLine: 625, EndLine: 632}}},
		{ID: "@babel/plugin-transform-modules-systemjs@7.4.4", Name: "@babel/plugin-transform-modules-systemjs", Version: "7.4.4", Locations: []types.Location{{StartLine: 634, EndLine: 640}}},
		{ID: "@babel/plugin-transform-modules-umd@7.2.0", Name: "@babel/plugin-transform-modules-umd", Version: "7.2.0", Locations: []types.Location{{StartLine: 642, EndLine: 648}}},
		{ID: "@babel/plugin-transform-named-capturing-groups-regex@7.4.4", Name: "@babel/plugin-transform-named-capturing-groups-regex", Version: "7.4.4", Locations: []types.Location{{StartLine: 650, EndLine: 655}}},
		{ID: "@babel/plugin-transform-new-target@7.4.4", Name: "@babel/plugin-transform-new-target", Version: "7.4.4", Locations: []types.Location{{StartLine: 657, EndLine: 662}}},
		{ID: "@babel/plugin-transform-object-super@7.2.0", Name: "@babel/plugin-transform-object-super", Version: "7.2.0", Locations: []types.Location{{StartLine: 664, EndLine: 670}}},
		{ID: "@babel/plugin-transform-parameters@7.4.4", Name: "@babel/plugin-transform-parameters", Version: "7.4.4", Locations: []types.Location{{StartLine: 672, EndLine: 679}}},
		{ID: "@babel/plugin-transform-property-literals@7.2.0", Name: "@babel/plugin-transform-property-literals", Version: "7.2.0", Locations: []types.Location{{StartLine: 681, EndLine: 686}}},
		{ID: "@babel/plugin-transform-react-constant-elements@7.0.0", Name: "@babel/plugin-transform-react-constant-elements", Version: "7.0.0", Locations: []types.Location{{StartLine: 688, EndLine: 694}}},
		{ID: "@babel/plugin-transform-react-constant-elements@7.2.0", Name: "@babel/plugin-transform-react-constant-elements", Version: "7.2.0", Locations: []types.Location{{StartLine: 696, EndLine: 702}}},
		{ID: "@babel/plugin-transform-react-display-name@7.0.0", Name: "@babel/plugin-transform-react-display-name", Version: "7.0.0", Locations: []types.Location{{StartLine: 704, EndLine: 709}}},
		{ID: "@babel/plugin-transform-react-display-name@7.2.0", Name: "@babel/plugin-transform-react-display-name", Version: "7.2.0", Locations: []types.Location{{StartLine: 711, EndLine: 716}}},
		{ID: "@babel/plugin-transform-react-jsx-self@7.2.0", Name: "@babel/plugin-transform-react-jsx-self", Version: "7.2.0", Locations: []types.Location{{StartLine: 718, EndLine: 724}}},
		{ID: "@babel/plugin-transform-react-jsx-source@7.2.0", Name: "@babel/plugin-transform-react-jsx-source", Version: "7.2.0", Locations: []types.Location{{StartLine: 726, EndLine: 732}}},
		{ID: "@babel/plugin-transform-react-jsx@7.3.0", Name: "@babel/plugin-transform-react-jsx", Version: "7.3.0", Locations: []types.Location{{StartLine: 734, EndLine: 741}}},
		{ID: "@babel/plugin-transform-regenerator@7.4.4", Name: "@babel/plugin-transform-regenerator", Version: "7.4.4", Locations: []types.Location{{StartLine: 743, EndLine: 748}}},
		{ID: "@babel/plugin-transform-reserved-words@7.2.0", Name: "@babel/plugin-transform-reserved-words", Version: "7.2.0", Locations: []types.Location{{StartLine: 750, EndLine: 755}}},
		{ID: "@babel/plugin-transform-runtime@7.1.0", Name: "@babel/plugin-transform-runtime", Version: "7.1.0", Locations: []types.Location{{StartLine: 757, EndLine: 765}}},
		{ID: "@babel/plugin-transform-shorthand-properties@7.2.0", Name: "@babel/plugin-transform-shorthand-properties", Version: "7.2.0", Locations: []types.Location{{StartLine: 767, EndLine: 772}}},
		{ID: "@babel/plugin-transform-spread@7.2.2", Name: "@babel/plugin-transform-spread", Version: "7.2.2", Locations: []types.Location{{StartLine: 774, EndLine: 779}}},
		{ID: "@babel/plugin-transform-sticky-regex@7.2.0", Name: "@babel/plugin-transform-sticky-regex", Version: "7.2.0", Locations: []types.Location{{StartLine: 781, EndLine: 787}}},
		{ID: "@babel/plugin-transform-template-literals@7.4.4", Name: "@babel/plugin-transform-template-literals", Version: "7.4.4", Locations: []types.Location{{StartLine: 789, EndLine: 795}}},
		{ID: "@babel/plugin-transform-typeof-symbol@7.2.0", Name: "@babel/plugin-transform-typeof-symbol", Version: "7.2.0", Locations: []types.Location{{StartLine: 797, EndLine: 802}}},
		{ID: "@babel/plugin-transform-typescript@7.4.4", Name: "@babel/plugin-transform-typescript", Version: "7.4.4", Locations: []types.Location{{StartLine: 804, EndLine: 810}}},
		{ID: "@babel/plugin-transform-unicode-regex@7.4.4", Name: "@babel/plugin-transform-unicode-regex", Version: "7.4.4", Locations: []types.Location{{StartLine: 812, EndLine: 819}}},
		{ID: "@babel/preset-env@7.1.0", Name: "@babel/preset-env", Version: "7.1.0", Locations: []types.Location{{StartLine: 821, EndLine: 866}}},
		{ID: "@babel/preset-env@7.4.4", Name: "@babel/preset-env", Version: "7.4.4", Locations: []types.Location{{StartLine: 868, EndLine: 920}}},
		{ID: "@babel/preset-flow@7.0.0", Name: "@babel/preset-flow", Version: "7.0.0", Locations: []types.Location{{StartLine: 922, EndLine: 928}}},
		{ID: "@babel/preset-react@7.0.0", Name: "@babel/preset-react", Version: "7.0.0", Locations: []types.Location{{StartLine: 930, EndLine: 939}}},
		{ID: "@babel/preset-typescript@7.1.0", Name: "@babel/preset-typescript", Version: "7.1.0", Locations: []types.Location{{StartLine: 941, EndLine: 947}}},
		{ID: "@babel/register@7.4.4", Name: "@babel/register", Version: "7.4.4", Locations: []types.Location{{StartLine: 949, EndLine: 959}}},
		{ID: "@babel/runtime@7.0.0", Name: "@babel/runtime", Version: "7.0.0", Locations: []types.Location{{StartLine: 961, EndLine: 966}}},
		{ID: "@babel/runtime@7.4.4", Name: "@babel/runtime", Version: "7.4.4", Locations: []types.Location{{StartLine: 968, EndLine: 973}}},
		{ID: "@babel/template@7.0.0-beta.44", Name: "@babel/template", Version: "7.0.0-beta.44", Locations: []types.Location{{StartLine: 975, EndLine: 983}}},
		{ID: "@babel/template@7.4.4", Name: "@babel/template", Version: "7.4.4", Locations: []types.Location{{StartLine: 985, EndLine: 992}}},
		{ID: "@babel/traverse@7.0.0-beta.44", Name: "@babel/traverse", Version: "7.0.0-beta.44", Locations: []types.Location{{StartLine: 994, EndLine: 1008}}},
		{ID: "@babel/traverse@7.4.4", Name: "@babel/traverse", Version: "7.4.4", Locations: []types.Location{{StartLine: 1010, EndLine: 1023}}},
		{ID: "@babel/types@7.0.0-beta.44", Name: "@babel/types", Version: "7.0.0-beta.44", Locations: []types.Location{{StartLine: 1025, EndLine: 1032}}},
		{ID: "@babel/types@7.4.4", Name: "@babel/types", Version: "7.4.4", Locations: []types.Location{{StartLine: 1034, EndLine: 1041}}},
		{ID: "@emotion/cache@0.8.8", Name: "@emotion/cache", Version: "0.8.8", Locations: []types.Location{{StartLine: 1043, EndLine: 1050}}},
		{ID: "@emotion/core@0.13.1", Name: "@emotion/core", Version: "0.13.1", Locations: []types.Location{{StartLine: 1052, EndLine: 1061}}},
		{ID: "@emotion/css@0.9.8", Name: "@emotion/css", Version: "0.9.8", Locations: []types.Location{{StartLine: 1063, EndLine: 1069}}},
		{ID: "@emotion/hash@0.6.6", Name: "@emotion/hash", Version: "0.6.6", Locations: []types.Location{{StartLine: 1071, EndLine: 1074}}},
		{ID: "@emotion/is-prop-valid@0.6.8", Name: "@emotion/is-prop-valid", Version: "0.6.8", Locations: []types.Location{{StartLine: 1076, EndLine: 1081}}},
		{ID: "@emotion/is-prop-valid@0.7.3", Name: "@emotion/is-prop-valid", Version: "0.7.3", Locations: []types.Location{{StartLine: 1083, EndLine: 1088}}},
		{ID: "@emotion/memoize@0.7.1", Name: "@emotion/memoize", Version: "0.7.1", Locations: []types.Location{{StartLine: 1090, EndLine: 1093}}},
		{ID: "@emotion/memoize@0.6.6", Name: "@emotion/memoize", Version: "0.6.6", Locations: []types.Location{{StartLine: 1095, EndLine: 1098}}},
		{ID: "@emotion/provider@0.11.2", Name: "@emotion/provider", Version: "0.11.2", Locations: []types.Location{{StartLine: 1100, EndLine: 1106}}},
		{ID: "@emotion/serialize@0.9.1", Name: "@emotion/serialize", Version: "0.9.1", Locations: []types.Location{{StartLine: 1108, EndLine: 1116}}},
		{ID: "@emotion/sheet@0.8.1", Name: "@emotion/sheet", Version: "0.8.1", Locations: []types.Location{{StartLine: 1118, EndLine: 1121}}},
		{ID: "@emotion/styled-base@0.10.6", Name: "@emotion/styled-base", Version: "0.10.6", Locations: []types.Location{{StartLine: 1123, EndLine: 1130}}},
		{ID: "@emotion/styled@0.10.6", Name: "@emotion/styled", Version: "0.10.6", Locations: []types.Location{{StartLine: 1132, EndLine: 1137}}},
		{ID: "@emotion/stylis@0.7.1", Name: "@emotion/stylis", Version: "0.7.1", Locations: []types.Location{{StartLine: 1139, EndLine: 1142}}},
		{ID: "@emotion/unitless@0.6.7", Name: "@emotion/unitless", Version: "0.6.7", Locations: []types.Location{{StartLine: 1144, EndLine: 1147}}},
		{ID: "@emotion/unitless@0.7.3", Name: "@emotion/unitless", Version: "0.7.3", Locations: []types.Location{{StartLine: 1149, EndLine: 1152}}},
		{ID: "@emotion/utils@0.8.2", Name: "@emotion/utils", Version: "0.8.2", Locations: []types.Location{{StartLine: 1154, EndLine: 1157}}},
		{ID: "@emotion/weak-memoize@0.1.3", Name: "@emotion/weak-memoize", Version: "0.1.3", Locations: []types.Location{{StartLine: 1159, EndLine: 1162}}},
		{ID: "@icons/material@0.2.4", Name: "@icons/material", Version: "0.2.4", Locations: []types.Location{{StartLine: 1164, EndLine: 1167}}},
		{ID: "@loadable/component@5.10.1", Name: "@loadable/component", Version: "5.10.1", Locations: []types.Location{{StartLine: 1169, EndLine: 1175}}},
		{ID: "@material-ui/core@3.9.3", Name: "@material-ui/core", Version: "3.9.3", Locations: []types.Location{{StartLine: 1177, EndLine: 1208}}},
		{ID: "@material-ui/icons@3.0.2", Name: "@material-ui/icons", Version: "3.0.2", Locations: []types.Location{{StartLine: 1210, EndLine: 1216}}},
		{ID: "@material-ui/system@3.0.0-alpha.2", Name: "@material-ui/system", Version: "3.0.0-alpha.2", Locations: []types.Location{{StartLine: 1218, EndLine: 1226}}},
		{ID: "@material-ui/utils@3.0.0-alpha.3", Name: "@material-ui/utils", Version: "3.0.0-alpha.3", Locations: []types.Location{{StartLine: 1228, EndLine: 1235}}},
		{ID: "@mrmlnc/readdir-enhanced@2.2.1", Name: "@mrmlnc/readdir-enhanced", Version: "2.2.1", Locations: []types.Location{{StartLine: 1237, EndLine: 1243}}},
		{ID: "@nodelib/fs.stat@1.1.3", Name: "@nodelib/fs.stat", Version: "1.1.3", Locations: []types.Location{{StartLine: 1245, EndLine: 1248}}},
		{ID: "@octokit/rest@15.18.1", Name: "@octokit/rest", Version: "15.18.1", Locations: []types.Location{{StartLine: 1250, EndLine: 1263}}},
		{ID: "@samverschueren/stream-to-observable@0.3.0", Name: "@samverschueren/stream-to-observable", Version: "0.3.0", Locations: []types.Location{{StartLine: 1265, EndLine: 1270}}},
		{ID: "@storybook/addon-actions@4.1.18", Name: "@storybook/addon-actions", Version: "4.1.18", Locations: []types.Location{{StartLine: 1272, EndLine: 1290}}},
		{ID: "@storybook/addon-info@4.1.18", Name: "@storybook/addon-info", Version: "4.1.18", Locations: []types.Location{{StartLine: 1292, EndLine: 1307}}},
		{ID: "@storybook/addon-knobs@4.1.18", Name: "@storybook/addon-knobs", Version: "4.1.18", Locations: []types.Location{{StartLine: 1309, EndLine: 1327}}},
		{ID: "@storybook/addons@4.1.18", Name: "@storybook/addons", Version: "4.1.18", Locations: []types.Location{{StartLine: 1329, EndLine: 1337}}},
		{ID: "@storybook/channel-postmessage@4.1.18", Name: "@storybook/channel-postmessage", Version: "4.1.18", Locations: []types.Location{{StartLine: 1339, EndLine: 1346}}},
		{ID: "@storybook/channels@4.1.18", Name: "@storybook/channels", Version: "4.1.18", Locations: []types.Location{{StartLine: 1348, EndLine: 1351}}},
		{ID: "@storybook/cli@4.1.18", Name: "@storybook/cli", Version: "4.1.18", Locations: []types.Location{{StartLine: 1353, EndLine: 1372}}},
		{ID: "@storybook/client-logger@4.1.18", Name: "@storybook/client-logger", Version: "4.1.18", Locations: []types.Location{{StartLine: 1374, EndLine: 1377}}},
		{ID: "@storybook/codemod@4.1.18", Name: "@storybook/codemod", Version: "4.1.18", Locations: []types.Location{{StartLine: 1379, EndLine: 1386}}},
		{ID: "@storybook/components@4.1.18", Name: "@storybook/components", Version: "4.1.18", Locations: []types.Location{{StartLine: 1388, EndLine: 1402}}},
		{ID: "@storybook/core-events@4.1.18", Name: "@storybook/core-events", Version: "4.1.18", Locations: []types.Location{{StartLine: 1404, EndLine: 1407}}},
		{ID: "@storybook/core@4.1.18", Name: "@storybook/core", Version: "4.1.18", Locations: []types.Location{{StartLine: 1409, EndLine: 1477}}},
		{ID: "@storybook/mantra-core@1.7.2", Name: "@storybook/mantra-core", Version: "1.7.2", Locations: []types.Location{{StartLine: 1479, EndLine: 1486}}},
		{ID: "@storybook/node-logger@4.1.18", Name: "@storybook/node-logger", Version: "4.1.18", Locations: []types.Location{{StartLine: 1488, EndLine: 1497}}},
		{ID: "@storybook/podda@1.2.3", Name: "@storybook/podda", Version: "1.2.3", Locations: []types.Location{{StartLine: 1499, EndLine: 1505}}},
		{ID: "@storybook/react-komposer@2.0.5", Name: "@storybook/react-komposer", Version: "2.0.5", Locations: []types.Location{{StartLine: 1507, EndLine: 1516}}},
		{ID: "@storybook/react-simple-di@1.3.0", Name: "@storybook/react-simple-di", Version: "1.3.0", Locations: []types.Location{{StartLine: 1518, EndLine: 1526}}},
		{ID: "@storybook/react-stubber@1.0.1", Name: "@storybook/react-stubber", Version: "1.0.1", Locations: []types.Location{{StartLine: 1528, EndLine: 1533}}},
		{ID: "@storybook/react@4.1.18", Name: "@storybook/react", Version: "4.1.18", Locations: []types.Location{{StartLine: 1535, EndLine: 1559}}},
		{ID: "@storybook/ui@4.1.18", Name: "@storybook/ui", Version: "4.1.18", Locations: []types.Location{{StartLine: 1561, EndLine: 1587}}},
		{ID: "@svgr/babel-plugin-add-jsx-attribute@4.2.0", Name: "@svgr/babel-plugin-add-jsx-attribute", Version: "4.2.0", Locations: []types.Location{{StartLine: 1589, EndLine: 1592}}},
		{ID: "@svgr/babel-plugin-remove-jsx-attribute@4.2.0", Name: "@svgr/babel-plugin-remove-jsx-attribute", Version: "4.2.0", Locations: []types.Location{{StartLine: 1594, EndLine: 1597}}},
		{ID: "@svgr/babel-plugin-remove-jsx-empty-expression@4.2.0", Name: "@svgr/babel-plugin-remove-jsx-empty-expression", Version: "4.2.0", Locations: []types.Location{{StartLine: 1599, EndLine: 1602}}},
		{ID: "@svgr/babel-plugin-replace-jsx-attribute-value@4.2.0", Name: "@svgr/babel-plugin-replace-jsx-attribute-value", Version: "4.2.0", Locations: []types.Location{{StartLine: 1604, EndLine: 1607}}},
		{ID: "@svgr/babel-plugin-svg-dynamic-title@4.2.0", Name: "@svgr/babel-plugin-svg-dynamic-title", Version: "4.2.0", Locations: []types.Location{{StartLine: 1609, EndLine: 1612}}},
		{ID: "@svgr/babel-plugin-svg-em-dimensions@4.2.0", Name: "@svgr/babel-plugin-svg-em-dimensions", Version: "4.2.0", Locations: []types.Location{{StartLine: 1614, EndLine: 1617}}},
		{ID: "@svgr/babel-plugin-transform-react-native-svg@4.2.0", Name: "@svgr/babel-plugin-transform-react-native-svg", Version: "4.2.0", Locations: []types.Location{{StartLine: 1619, EndLine: 1622}}},
		{ID: "@svgr/babel-plugin-transform-svg-component@4.2.0", Name: "@svgr/babel-plugin-transform-svg-component", Version: "4.2.0", Locations: []types.Location{{StartLine: 1624, EndLine: 1627}}},
		{ID: "@svgr/babel-preset@4.2.0", Name: "@svgr/babel-preset", Version: "4.2.0", Locations: []types.Location{{StartLine: 1629, EndLine: 1641}}},
		{ID: "@svgr/core@4.2.0", Name: "@svgr/core", Version: "4.2.0", Locations: []types.Location{{StartLine: 1643, EndLine: 1650}}},
		{ID: "@svgr/hast-util-to-babel-ast@4.2.0", Name: "@svgr/hast-util-to-babel-ast", Version: "4.2.0", Locations: []types.Location{{StartLine: 1652, EndLine: 1657}}},
		{ID: "@svgr/plugin-jsx@4.2.0", Name: "@svgr/plugin-jsx", Version: "4.2.0", Locations: []types.Location{{StartLine: 1659, EndLine: 1669}}},
		{ID: "@svgr/plugin-svgo@4.2.0", Name: "@svgr/plugin-svgo", Version: "4.2.0", Locations: []types.Location{{StartLine: 1671, EndLine: 1678}}},
		{ID: "@svgr/webpack@4.2.0", Name: "@svgr/webpack", Version: "4.2.0", Locations: []types.Location{{StartLine: 1680, EndLine: 1692}}},
		{ID: "@types/events@3.0.0", Name: "@types/events", Version: "3.0.0", Locations: []types.Location{{StartLine: 1694, EndLine: 1697}}},
		{ID: "@types/glob@7.1.1", Name: "@types/glob", Version: "7.1.1", Locations: []types.Location{{StartLine: 1699, EndLine: 1706}}},
		{ID: "@types/jss@9.5.8", Name: "@types/jss", Version: "9.5.8", Locations: []types.Location{{StartLine: 1708, EndLine: 1714}}},
		{ID: "@types/minimatch@3.0.3", Name: "@types/minimatch", Version: "3.0.3", Locations: []types.Location{{StartLine: 1716, EndLine: 1719}}},
		{ID: "@types/node@12.0.2", Name: "@types/node", Version: "12.0.2", Locations: []types.Location{{StartLine: 1721, EndLine: 1724}}},
		{ID: "@types/prop-types@15.7.1", Name: "@types/prop-types", Version: "15.7.1", Locations: []types.Location{{StartLine: 1726, EndLine: 1729}}},
		{ID: "@types/q@1.5.2", Name: "@types/q", Version: "1.5.2", Locations: []types.Location{{StartLine: 1731, EndLine: 1734}}},
		{ID: "@types/react-transition-group@2.9.1", Name: "@types/react-transition-group", Version: "2.9.1", Locations: []types.Location{{StartLine: 1736, EndLine: 1741}}},
		{ID: "@types/react@16.8.17", Name: "@types/react", Version: "16.8.17", Locations: []types.Location{{StartLine: 1743, EndLine: 1749}}},
		{ID: "@types/unist@2.0.3", Name: "@types/unist", Version: "2.0.3", Locations: []types.Location{{StartLine: 1751, EndLine: 1754}}},
		{ID: "@types/vfile-message@1.0.1", Name: "@types/vfile-message", Version: "1.0.1", Locations: []types.Location{{StartLine: 1756, EndLine: 1762}}},
		{ID: "@types/vfile@3.0.2", Name: "@types/vfile", Version: "3.0.2", Locations: []types.Location{{StartLine: 1764, EndLine: 1771}}},
		{ID: "@webassemblyjs/ast@1.8.5", Name: "@webassemblyjs/ast", Version: "1.8.5", Locations: []types.Location{{StartLine: 1773, EndLine: 1780}}},
		{ID: "@webassemblyjs/floating-point-hex-parser@1.8.5", Name: "@webassemblyjs/floating-point-hex-parser", Version: "1.8.5", Locations: []types.Location{{StartLine: 1782, EndLine: 1785}}},
		{ID: "@webassemblyjs/helper-api-error@1.8.5", Name: "@webassemblyjs/helper-api-error", Version: "1.8.5", Locations: []types.Location{{StartLine: 1787, EndLine: 1790}}},
		{ID: "@webassemblyjs/helper-buffer@1.8.5", Name: "@webassemblyjs/helper-buffer", Version: "1.8.5", Locations: []types.Location{{StartLine: 1792, EndLine: 1795}}},
		{ID: "@webassemblyjs/helper-code-frame@1.8.5", Name: "@webassemblyjs/helper-code-frame", Version: "1.8.5", Locations: []types.Location{{StartLine: 1797, EndLine: 1802}}},
		{ID: "@webassemblyjs/helper-fsm@1.8.5", Name: "@webassemblyjs/helper-fsm", Version: "1.8.5", Locations: []types.Location{{StartLine: 1804, EndLine: 1807}}},
		{ID: "@webassemblyjs/helper-module-context@1.8.5", Name: "@webassemblyjs/helper-module-context", Version: "1.8.5", Locations: []types.Location{{StartLine: 1809, EndLine: 1815}}},
		{ID: "@webassemblyjs/helper-wasm-bytecode@1.8.5", Name: "@webassemblyjs/helper-wasm-bytecode", Version: "1.8.5", Locations: []types.Location{{StartLine: 1817, EndLine: 1820}}},
		{ID: "@webassemblyjs/helper-wasm-section@1.8.5", Name: "@webassemblyjs/helper-wasm-section", Version: "1.8.5", Locations: []types.Location{{StartLine: 1822, EndLine: 1830}}},
		{ID: "@webassemblyjs/ieee754@1.8.5", Name: "@webassemblyjs/ieee754", Version: "1.8.5", Locations: []types.Location{{StartLine: 1832, EndLine: 1837}}},
		{ID: "@webassemblyjs/leb128@1.8.5", Name: "@webassemblyjs/leb128", Version: "1.8.5", Locations: []types.Location{{StartLine: 1839, EndLine: 1844}}},
		{ID: "@webassemblyjs/utf8@1.8.5", Name: "@webassemblyjs/utf8", Version: "1.8.5", Locations: []types.Location{{StartLine: 1846, EndLine: 1849}}},
		{ID: "@webassemblyjs/wasm-edit@1.8.5", Name: "@webassemblyjs/wasm-edit", Version: "1.8.5", Locations: []types.Location{{StartLine: 1851, EndLine: 1863}}},
		{ID: "@webassemblyjs/wasm-gen@1.8.5", Name: "@webassemblyjs/wasm-gen", Version: "1.8.5", Locations: []types.Location{{StartLine: 1865, EndLine: 1874}}},
		{ID: "@webassemblyjs/wasm-opt@1.8.5", Name: "@webassemblyjs/wasm-opt", Version: "1.8.5", Locations: []types.Location{{StartLine: 1876, EndLine: 1884}}},
		{ID: "@webassemblyjs/wasm-parser@1.8.5", Name: "@webassemblyjs/wasm-parser", Version: "1.8.5", Locations: []types.Location{{StartLine: 1886, EndLine: 1896}}},
		{ID: "@webassemblyjs/wast-parser@1.8.5", Name: "@webassemblyjs/wast-parser", Version: "1.8.5", Locations: []types.Location{{StartLine: 1898, EndLine: 1908}}},
		{ID: "@webassemblyjs/wast-printer@1.8.5", Name: "@webassemblyjs/wast-printer", Version: "1.8.5", Locations: []types.Location{{StartLine: 1910, EndLine: 1917}}},
		{ID: "@xtuc/ieee754@1.2.0", Name: "@xtuc/ieee754", Version: "1.2.0", Locations: []types.Location{{StartLine: 1919, EndLine: 1922}}},
		{ID: "@xtuc/long@4.2.2", Name: "@xtuc/long", Version: "4.2.2", Locations: []types.Location{{StartLine: 1924, EndLine: 1927}}},
		{ID: "JSONStream@1.3.5", Name: "JSONStream", Version: "1.3.5", Locations: []types.Location{{StartLine: 1929, EndLine: 1935}}},
		{ID: "abab@2.0.0", Name: "abab", Version: "2.0.0", Locations: []types.Location{{StartLine: 1937, EndLine: 1940}}},
		{ID: "abbrev@1.1.1", Name: "abbrev", Version: "1.1.1", Locations: []types.Location{{StartLine: 1942, EndLine: 1945}}},
		{ID: "accepts@1.3.7", Name: "accepts", Version: "1.3.7", Locations: []types.Location{{StartLine: 1947, EndLine: 1953}}},
		{ID: "acorn-dynamic-import@4.0.0", Name: "acorn-dynamic-import", Version: "4.0.0", Locations: []types.Location{{StartLine: 1955, EndLine: 1958}}},
		{ID: "acorn-globals@4.3.2", Name: "acorn-globals", Version: "4.3.2", Locations: []types.Location{{StartLine: 1960, EndLine: 1966}}},
		{ID: "acorn-jsx@5.0.1", Name: "acorn-jsx", Version: "5.0.1", Locations: []types.Location{{StartLine: 1968, EndLine: 1971}}},
		{ID: "acorn-walk@6.1.1", Name: "acorn-walk", Version: "6.1.1", Locations: []types.Location{{StartLine: 1973, EndLine: 1976}}},
		{ID: "acorn@5.7.3", Name: "acorn", Version: "5.7.3", Locations: []types.Location{{StartLine: 1978, EndLine: 1981}}},
		{ID: "acorn@6.1.1", Name: "acorn", Version: "6.1.1", Locations: []types.Location{{StartLine: 1983, EndLine: 1986}}},
		{ID: "address@1.0.3", Name: "address", Version: "1.0.3", Locations: []types.Location{{StartLine: 1988, EndLine: 1991}}},
		{ID: "address@1.1.0", Name: "address", Version: "1.1.0", Locations: []types.Location{{StartLine: 1993, EndLine: 1996}}},
		{ID: "after@0.8.2", Name: "after", Version: "0.8.2", Locations: []types.Location{{StartLine: 1998, EndLine: 2001}}},
		{ID: "agent-base@4.2.1", Name: "agent-base", Version: "4.2.1", Locations: []types.Location{{StartLine: 2003, EndLine: 2008}}},
		{ID: "agentkeepalive@3.5.2", Name: "agentkeepalive", Version: "3.5.2", Locations: []types.Location{{StartLine: 2010, EndLine: 2015}}},
		{ID: "airbnb-js-shims@2.2.0", Name: "airbnb-js-shims", Version: "2.2.0", Locations: []types.Location{{StartLine: 2017, EndLine: 2038}}},
		{ID: "airbnb-prop-types@2.13.2", Name: "airbnb-prop-types", Version: "2.13.2", Locations: []types.Location{{StartLine: 2040, EndLine: 2054}}},
		{ID: "ajv-errors@1.0.1", Name: "ajv-errors", Version: "1.0.1", Locations: []types.Location{{StartLine: 2056, EndLine: 2059}}},
		{ID: "ajv-keywords@3.4.0", Name: "ajv-keywords", Version: "3.4.0", Locations: []types.Location{{StartLine: 2061, EndLine: 2064}}},
		{ID: "ajv@6.10.0", Name: "ajv", Version: "6.10.0", Locations: []types.Location{{StartLine: 2066, EndLine: 2074}}},
		{ID: "ansi-align@2.0.0", Name: "ansi-align", Version: "2.0.0", Locations: []types.Location{{StartLine: 2076, EndLine: 2081}}},
		{ID: "ansi-align@3.0.0", Name: "ansi-align", Version: "3.0.0", Locations: []types.Location{{StartLine: 2083, EndLine: 2088}}},
		{ID: "ansi-colors@3.2.4", Name: "ansi-colors", Version: "3.2.4", Locations: []types.Location{{StartLine: 2090, EndLine: 2093}}},
		{ID: "ansi-escapes@1.4.0", Name: "ansi-escapes", Version: "1.4.0", Locations: []types.Location{{StartLine: 2095, EndLine: 2098}}},
		{ID: "ansi-escapes@3.2.0", Name: "ansi-escapes", Version: "3.2.0", Locations: []types.Location{{StartLine: 2100, EndLine: 2103}}},
		{ID: "ansi-html@0.0.7", Name: "ansi-html", Version: "0.0.7", Locations: []types.Location{{StartLine: 2105, EndLine: 2108}}},
		{ID: "ansi-regex@2.1.1", Name: "ansi-regex", Version: "2.1.1", Locations: []types.Location{{StartLine: 2110, EndLine: 2113}}},
		{ID: "ansi-regex@3.0.0", Name: "ansi-regex", Version: "3.0.0", Locations: []types.Location{{StartLine: 2115, EndLine: 2118}}},
		{ID: "ansi-regex@4.1.0", Name: "ansi-regex", Version: "4.1.0", Locations: []types.Location{{StartLine: 2120, EndLine: 2123}}},
		{ID: "ansi-styles@2.2.1", Name: "ansi-styles", Version: "2.2.1", Locations: []types.Location{{StartLine: 2125, EndLine: 2128}}},
		{ID: "ansi-styles@3.2.1", Name: "ansi-styles", Version: "3.2.1", Locations: []types.Location{{StartLine: 2130, EndLine: 2135}}},
		{ID: "ansi-styles@1.0.0", Name: "ansi-styles", Version: "1.0.0", Locations: []types.Location{{StartLine: 2137, EndLine: 2140}}},
		{ID: "ansicolors@0.3.2", Name: "ansicolors", Version: "0.3.2", Locations: []types.Location{{StartLine: 2142, EndLine: 2145}}},
		{ID: "ansistyles@0.1.3", Name: "ansistyles", Version: "0.1.3", Locations: []types.Location{{StartLine: 2147, EndLine: 2150}}},
		{ID: "any-observable@0.3.0", Name: "any-observable", Version: "0.3.0", Locations: []types.Location{{StartLine: 2152, EndLine: 2155}}},
		{ID: "anymatch@1.3.2", Name: "anymatch", Version: "1.3.2", Locations: []types.Location{{StartLine: 2157, EndLine: 2163}}},
		{ID: "anymatch@2.0.0", Name: "anymatch", Version: "2.0.0", Locations: []types.Location{{StartLine: 2165, EndLine: 2171}}},
		{ID: "app-root-dir@1.0.2", Name: "app-root-dir", Version: "1.0.2", Locations: []types.Location{{StartLine: 2173, EndLine: 2176}}},
		{ID: "append-transform@0.4.0", Name: "append-transform", Version: "0.4.0", Locations: []types.Location{{StartLine: 2178, EndLine: 2183}}},
		{ID: "aproba@1.2.0", Name: "aproba", Version: "1.2.0", Locations: []types.Location{{StartLine: 2185, EndLine: 2188}}},
		{ID: "aproba@2.0.0", Name: "aproba", Version: "2.0.0", Locations: []types.Location{{StartLine: 2190, EndLine: 2193}}},
		{ID: "archy@1.0.0", Name: "archy", Version: "1.0.0", Locations: []types.Location{{StartLine: 2195, EndLine: 2198}}},
		{ID: "are-we-there-yet@1.1.5", Name: "are-we-there-yet", Version: "1.1.5", Locations: []types.Location{{StartLine: 2200, EndLine: 2206}}},
		{ID: "argparse@1.0.10", Name: "argparse", Version: "1.0.10", Locations: []types.Location{{StartLine: 2208, EndLine: 2213}}},
		{ID: "aria-query@3.0.0", Name: "aria-query", Version: "3.0.0", Locations: []types.Location{{StartLine: 2215, EndLine: 2221}}},
		{ID: "arr-diff@2.0.0", Name: "arr-diff", Version: "2.0.0", Locations: []types.Location{{StartLine: 2223, EndLine: 2228}}},
		{ID: "arr-diff@4.0.0", Name: "arr-diff", Version: "4.0.0", Locations: []types.Location{{StartLine: 2230, EndLine: 2233}}},
		{ID: "arr-flatten@1.1.0", Name: "arr-flatten", Version: "1.1.0", Locations: []types.Location{{StartLine: 2235, EndLine: 2238}}},
		{ID: "arr-union@3.1.0", Name: "arr-union", Version: "3.1.0", Locations: []types.Location{{StartLine: 2240, EndLine: 2243}}},
		{ID: "array-equal@1.0.0", Name: "array-equal", Version: "1.0.0", Locations: []types.Location{{StartLine: 2245, EndLine: 2248}}},
		{ID: "array-filter@1.0.0", Name: "array-filter", Version: "1.0.0", Locations: []types.Location{{StartLine: 2250, EndLine: 2253}}},
		{ID: "array-filter@0.0.1", Name: "array-filter", Version: "0.0.1", Locations: []types.Location{{StartLine: 2255, EndLine: 2258}}},
		{ID: "array-flatten@1.1.1", Name: "array-flatten", Version: "1.1.1", Locations: []types.Location{{StartLine: 2260, EndLine: 2263}}},
		{ID: "array-flatten@2.1.2", Name: "array-flatten", Version: "2.1.2", Locations: []types.Location{{StartLine: 2265, EndLine: 2268}}},
		{ID: "array-includes@3.0.3", Name: "array-includes", Version: "3.0.3", Locations: []types.Location{{StartLine: 2270, EndLine: 2276}}},
		{ID: "array-map@0.0.0", Name: "array-map", Version: "0.0.0", Locations: []types.Location{{StartLine: 2278, EndLine: 2281}}},
		{ID: "array-reduce@0.0.0", Name: "array-reduce", Version: "0.0.0", Locations: []types.Location{{StartLine: 2283, EndLine: 2286}}},
		{ID: "array-union@1.0.2", Name: "array-union", Version: "1.0.2", Locations: []types.Location{{StartLine: 2288, EndLine: 2293}}},
		{ID: "array-uniq@1.0.3", Name: "array-uniq", Version: "1.0.3", Locations: []types.Location{{StartLine: 2295, EndLine: 2298}}},
		{ID: "array-unique@0.2.1", Name: "array-unique", Version: "0.2.1", Locations: []types.Location{{StartLine: 2300, EndLine: 2303}}},
		{ID: "array-unique@0.3.2", Name: "array-unique", Version: "0.3.2", Locations: []types.Location{{StartLine: 2305, EndLine: 2308}}},
		{ID: "array.prototype.find@2.0.4", Name: "array.prototype.find", Version: "2.0.4", Locations: []types.Location{{StartLine: 2310, EndLine: 2316}}},
		{ID: "array.prototype.flat@1.2.1", Name: "array.prototype.flat", Version: "1.2.1", Locations: []types.Location{{StartLine: 2318, EndLine: 2325}}},
		{ID: "array.prototype.flatmap@1.2.1", Name: "array.prototype.flatmap", Version: "1.2.1", Locations: []types.Location{{StartLine: 2327, EndLine: 2334}}},
		{ID: "arraybuffer.slice@0.0.7", Name: "arraybuffer.slice", Version: "0.0.7", Locations: []types.Location{{StartLine: 2336, EndLine: 2339}}},
		{ID: "arrify@1.0.1", Name: "arrify", Version: "1.0.1", Locations: []types.Location{{StartLine: 2341, EndLine: 2344}}},
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Locations: []types.Location{{StartLine: 2346, EndLine: 2349}}},
		{ID: "asn1.js@4.10.1", Name: "asn1.js", Version: "4.10.1", Locations: []types.Location{{StartLine: 2351, EndLine: 2358}}},
		{ID: "asn1@0.2.4", Name: "asn1", Version: "0.2.4", Locations: []types.Location{{StartLine: 2360, EndLine: 2365}}},
		{ID: "assert-plus@1.0.0", Name: "assert-plus", Version: "1.0.0", Locations: []types.Location{{StartLine: 2367, EndLine: 2370}}},
		{ID: "assert@1.5.0", Name: "assert", Version: "1.5.0", Locations: []types.Location{{StartLine: 2372, EndLine: 2378}}},
		{ID: "assign-symbols@1.0.0", Name: "assign-symbols", Version: "1.0.0", Locations: []types.Location{{StartLine: 2380, EndLine: 2383}}},
		{ID: "ast-types-flow@0.0.7", Name: "ast-types-flow", Version: "0.0.7", Locations: []types.Location{{StartLine: 2385, EndLine: 2388}}},
		{ID: "ast-types@0.11.3", Name: "ast-types", Version: "0.11.3", Locations: []types.Location{{StartLine: 2390, EndLine: 2393}}},
		{ID: "ast-types@0.11.5", Name: "ast-types", Version: "0.11.5", Locations: []types.Location{{StartLine: 2395, EndLine: 2398}}},
		{ID: "ast-types@0.11.7", Name: "ast-types", Version: "0.11.7", Locations: []types.Location{{StartLine: 2400, EndLine: 2403}}},
		{ID: "astral-regex@1.0.0", Name: "astral-regex", Version: "1.0.0", Locations: []types.Location{{StartLine: 2405, EndLine: 2408}}},
		{ID: "async-each@1.0.3", Name: "async-each", Version: "1.0.3", Locations: []types.Location{{StartLine: 2410, EndLine: 2413}}},
		{ID: "async-limiter@1.0.0", Name: "async-limiter", Version: "1.0.0", Locations: []types.Location{{StartLine: 2415, EndLine: 2418}}},
		{ID: "async@1.5.2", Name: "async", Version: "1.5.2", Locations: []types.Location{{StartLine: 2420, EndLine: 2423}}},
		{ID: "async@2.6.2", Name: "async", Version: "2.6.2", Locations: []types.Location{{StartLine: 2425, EndLine: 2430}}},
		{ID: "asynckit@0.4.0", Name: "asynckit", Version: "0.4.0", Locations: []types.Location{{StartLine: 2432, EndLine: 2435}}},
		{ID: "atob@2.1.2", Name: "atob", Version: "2.1.2", Locations: []types.Location{{StartLine: 2437, EndLine: 2440}}},
		{ID: "attr-accept@1.1.3", Name: "attr-accept", Version: "1.1.3", Locations: []types.Location{{StartLine: 2442, EndLine: 2447}}},
		{ID: "autodll-webpack-plugin@0.4.2", Name: "autodll-webpack-plugin", Version: "0.4.2", Locations: []types.Location{{StartLine: 2449, EndLine: 2463}}},
		{ID: "autoprefixer@8.6.5", Name: "autoprefixer", Version: "8.6.5", Locations: []types.Location{{StartLine: 2465, EndLine: 2475}}},
		{ID: "autoprefixer@9.5.1", Name: "autoprefixer", Version: "9.5.1", Locations: []types.Location{{StartLine: 2477, EndLine: 2487}}},
		{ID: "aws-sign2@0.7.0", Name: "aws-sign2", Version: "0.7.0", Locations: []types.Location{{StartLine: 2489, EndLine: 2492}}},
		{ID: "aws4@1.8.0", Name: "aws4", Version: "1.8.0", Locations: []types.Location{{StartLine: 2494, EndLine: 2497}}},
		{ID: "axios@0.18.0", Name: "axios", Version: "0.18.0", Locations: []types.Location{{StartLine: 2499, EndLine: 2505}}},
		{ID: "axobject-query@2.0.2", Name: "axobject-query", Version: "2.0.2", Locations: []types.Location{{StartLine: 2507, EndLine: 2512}}},
		{ID: "babel-cli@6.26.0", Name: "babel-cli", Version: "6.26.0", Locations: []types.Location{{StartLine: 2514, EndLine: 2534}}},
		{ID: "babel-code-frame@6.26.0", Name: "babel-code-frame", Version: "6.26.0", Locations: []types.Location{{StartLine: 2536, EndLine: 2543}}},
		{ID: "babel-core@6.26.3", Name: "babel-core", Version: "6.26.3", Locations: []types.Location{{StartLine: 2545, EndLine: 2568}}},
		{ID: "babel-eslint@8.2.6", Name: "babel-eslint", Version: "8.2.6", Locations: []types.Location{{StartLine: 2570, EndLine: 2580}}},
		{ID: "babel-generator@6.26.1", Name: "babel-generator", Version: "6.26.1", Locations: []types.Location{{StartLine: 2582, EndLine: 2594}}},
		{ID: "babel-helper-bindify-decorators@6.24.1", Name: "babel-helper-bindify-decorators", Version: "6.24.1", Locations: []types.Location{{StartLine: 2596, EndLine: 2603}}},
		{ID: "babel-helper-builder-binary-assignment-operator-visitor@6.24.1", Name: "babel-helper-builder-binary-assignment-operator-visitor", Version: "6.24.1", Locations: []types.Location{{StartLine: 2605, EndLine: 2612}}},
		{ID: "babel-helper-builder-react-jsx@6.26.0", Name: "babel-helper-builder-react-jsx", Version: "6.26.0", Locations: []types.Location{{StartLine: 2614, EndLine: 2621}}},
		{ID: "babel-helper-call-delegate@6.24.1", Name: "babel-helper-call-delegate", Version: "6.24.1", Locations: []types.Location{{StartLine: 2623, EndLine: 2631}}},
		{ID: "babel-helper-define-map@6.26.0", Name: "babel-helper-define-map", Version: "6.26.0", Locations: []types.Location{{StartLine: 2633, EndLine: 2641}}},
		{ID: "babel-helper-evaluate-path@0.5.0", Name: "babel-helper-evaluate-path", Version: "0.5.0", Locations: []types.Location{{StartLine: 2643, EndLine: 2646}}},
		{ID: "babel-helper-explode-assignable-expression@6.24.1", Name: "babel-helper-explode-assignable-expression", Version: "6.24.1", Locations: []types.Location{{StartLine: 2648, EndLine: 2655}}},
		{ID: "babel-helper-explode-class@6.24.1", Name: "babel-helper-explode-class", Version: "6.24.1", Locations: []types.Location{{StartLine: 2657, EndLine: 2665}}},
		{ID: "babel-helper-flip-expressions@0.4.3", Name: "babel-helper-flip-expressions", Version: "0.4.3", Locations: []types.Location{{StartLine: 2667, EndLine: 2670}}},
		{ID: "babel-helper-function-name@6.24.1", Name: "babel-helper-function-name", Version: "6.24.1", Locations: []types.Location{{StartLine: 2672, EndLine: 2681}}},
		{ID: "babel-helper-get-function-arity@6.24.1", Name: "babel-helper-get-function-arity", Version: "6.24.1", Locations: []types.Location{{StartLine: 2683, EndLine: 2689}}},
		{ID: "babel-helper-hoist-variables@6.24.1", Name: "babel-helper-hoist-variables", Version: "6.24.1", Locations: []types.Location{{StartLine: 2691, EndLine: 2697}}},
		{ID: "babel-helper-is-nodes-equiv@0.0.1", Name: "babel-helper-is-nodes-equiv", Version: "0.0.1", Locations: []types.Location{{StartLine: 2699, EndLine: 2702}}},
		{ID: "babel-helper-is-void-0@0.4.3", Name: "babel-helper-is-void-0", Version: "0.4.3", Locations: []types.Location{{StartLine: 2704, EndLine: 2707}}},
		{ID: "babel-helper-mark-eval-scopes@0.4.3", Name: "babel-helper-mark-eval-scopes", Version: "0.4.3", Locations: []types.Location{{StartLine: 2709, EndLine: 2712}}},
		{ID: "babel-helper-optimise-call-expression@6.24.1", Name: "babel-helper-optimise-call-expression", Version: "6.24.1", Locations: []types.Location{{StartLine: 2714, EndLine: 2720}}},
		{ID: "babel-helper-regex@6.26.0", Name: "babel-helper-regex", Version: "6.26.0", Locations: []types.Location{{StartLine: 2722, EndLine: 2729}}},
		{ID: "babel-helper-remap-async-to-generator@6.24.1", Name: "babel-helper-remap-async-to-generator", Version: "6.24.1", Locations: []types.Location{{StartLine: 2731, EndLine: 2740}}},
		{ID: "babel-helper-remove-or-void@0.4.3", Name: "babel-helper-remove-or-void", Version: "0.4.3", Locations: []types.Location{{StartLine: 2742, EndLine: 2745}}},
		{ID: "babel-helper-replace-supers@6.24.1", Name: "babel-helper-replace-supers", Version: "6.24.1", Locations: []types.Location{{StartLine: 2747, EndLine: 2757}}},
		{ID: "babel-helper-to-multiple-sequence-expressions@0.5.0", Name: "babel-helper-to-multiple-sequence-expressions", Version: "0.5.0", Locations: []types.Location{{StartLine: 2759, EndLine: 2762}}},
		{ID: "babel-helpers@6.24.1", Name: "babel-helpers", Version: "6.24.1", Locations: []types.Location{{StartLine: 2764, EndLine: 2770}}},
		{ID: "babel-jest@23.6.0", Name: "babel-jest", Version: "23.6.0", Locations: []types.Location{{StartLine: 2772, EndLine: 2778}}},
		{ID: "babel-loader@8.0.4", Name: "babel-loader", Version: "8.0.4", Locations: []types.Location{{StartLine: 2780, EndLine: 2788}}},
		{ID: "babel-loader@7.1.5", Name: "babel-loader", Version: "7.1.5", Locations: []types.Location{{StartLine: 2790, EndLine: 2797}}},
		{ID: "babel-messages@6.23.0", Name: "babel-messages", Version: "6.23.0", Locations: []types.Location{{StartLine: 2799, EndLine: 2804}}},
		{ID: "babel-plugin-check-es2015-constants@6.22.0", Name: "babel-plugin-check-es2015-constants", Version: "6.22.0", Locations: []types.Location{{StartLine: 2806, EndLine: 2811}}},
		{ID: "babel-plugin-dynamic-import-node@2.2.0", Name: "babel-plugin-dynamic-import-node", Version: "2.2.0", Locations: []types.Location{{StartLine: 2813, EndLine: 2818}}},
		{ID: "babel-plugin-istanbul@4.1.6", Name: "babel-plugin-istanbul", Version: "4.1.6", Locations: []types.Location{{StartLine: 2820, EndLine: 2828}}},
		{ID: "babel-plugin-jest-hoist@23.2.0", Name: "babel-plugin-jest-hoist", Version: "23.2.0", Locations: []types.Location{{StartLine: 2830, EndLine: 2833}}},
		{ID: "babel-plugin-macros@2.4.2", Name: "babel-plugin-macros", Version: "2.4.2", Locations: []types.Location{{StartLine: 2835, EndLine: 2841}}},
		{ID: "babel-plugin-macros@2.5.1", Name: "babel-plugin-macros", Version: "2.5.1", Locations: []types.Location{{StartLine: 2843, EndLine: 2850}}},
		{ID: "babel-plugin-minify-builtins@0.5.0", Name: "babel-plugin-minify-builtins", Version: "0.5.0", Locations: []types.Location{{StartLine: 2852, EndLine: 2855}}},
		{ID: "babel-plugin-minify-constant-folding@0.5.0", Name: "babel-plugin-minify-constant-folding", Version: "0.5.0", Locations: []types.Location{{StartLine: 2857, EndLine: 2862}}},
		{ID: "babel-plugin-minify-dead-code-elimination@0.5.0", Name: "babel-plugin-minify-dead-code-elimination", Version: "0.5.0", Locations: []types.Location{{StartLine: 2864, EndLine: 2872}}},
		{ID: "babel-plugin-minify-flip-comparisons@0.4.3", Name: "babel-plugin-minify-flip-comparisons", Version: "0.4.3", Locations: []types.Location{{StartLine: 2874, EndLine: 2879}}},
		{ID: "babel-plugin-minify-guarded-expressions@0.4.3", Name: "babel-plugin-minify-guarded-expressions", Version: "0.4.3", Locations: []types.Location{{StartLine: 2881, EndLine: 2886}}},
		{ID: "babel-plugin-minify-infinity@0.4.3", Name: "babel-plugin-minify-infinity", Version: "0.4.3", Locations: []types.Location{{StartLine: 2888, EndLine: 2891}}},
		{ID: "babel-plugin-minify-mangle-names@0.5.0", Name: "babel-plugin-minify-mangle-names", Version: "0.5.0", Locations: []types.Location{{StartLine: 2893, EndLine: 2898}}},
		{ID: "babel-plugin-minify-numeric-literals@0.4.3", Name: "babel-plugin-minify-numeric-literals", Version: "0.4.3", Locations: []types.Location{{StartLine: 2900, EndLine: 2903}}},
		{ID: "babel-plugin-minify-replace@0.5.0", Name: "babel-plugin-minify-replace", Version: "0.5.0", Locations: []types.Location{{StartLine: 2905, EndLine: 2908}}},
		{ID: "babel-plugin-minify-simplify@0.5.0", Name: "babel-plugin-minify-simplify", Version: "0.5.0", Locations: []types.Location{{StartLine: 2910, EndLine: 2917}}},
		{ID: "babel-plugin-minify-type-constructors@0.4.3", Name: "babel-plugin-minify-type-constructors", Version: "0.4.3", Locations: []types.Location{{StartLine: 2919, EndLine: 2924}}},
		{ID: "babel-plugin-named-asset-import@0.2.3", Name: "babel-plugin-named-asset-import", Version: "0.2.3", Locations: []types.Location{{StartLine: 2926, EndLine: 2929}}},
		{ID: "babel-plugin-react-docgen@2.0.2", Name: "babel-plugin-react-docgen", Version: "2.0.2", Locations: []types.Location{{StartLine: 2931, EndLine: 2938}}},
		{ID: "babel-plugin-react-html-attrs@2.1.0", Name: "babel-plugin-react-html-attrs", Version: "2.1.0", Locations: []types.Location{{StartLine: 2940, EndLine: 2943}}},
		{ID: "babel-plugin-styled-components@1.10.0", Name: "babel-plugin-styled-components", Version: "1.10.0", Locations: []types.Location{{StartLine: 2945, EndLine: 2953}}},
		{ID: "babel-plugin-syntax-async-functions@6.13.0", Name: "babel-plugin-syntax-async-functions", Version: "6.13.0", Locations: []types.Location{{StartLine: 2955, EndLine: 2958}}},
		{ID: "babel-plugin-syntax-async-generators@6.13.0", Name: "babel-plugin-syntax-async-generators", Version: "6.13.0", Locations: []types.Location{{StartLine: 2960, EndLine: 2963}}},
		{ID: "babel-plugin-syntax-class-constructor-call@6.18.0", Name: "babel-plugin-syntax-class-constructor-call", Version: "6.18.0", Locations: []types.Location{{StartLine: 2965, EndLine: 2968}}},
		{ID: "babel-plugin-syntax-class-properties@6.13.0", Name: "babel-plugin-syntax-class-properties", Version: "6.13.0", Locations: []types.Location{{StartLine: 2970, EndLine: 2973}}},
		{ID: "babel-plugin-syntax-decorators@6.13.0", Name: "babel-plugin-syntax-decorators", Version: "6.13.0", Locations: []types.Location{{StartLine: 2975, EndLine: 2978}}},
		{ID: "babel-plugin-syntax-dynamic-import@6.18.0", Name: "babel-plugin-syntax-dynamic-import", Version: "6.18.0", Locations: []types.Location{{StartLine: 2980, EndLine: 2983}}},
		{ID: "babel-plugin-syntax-exponentiation-operator@6.13.0", Name: "babel-plugin-syntax-exponentiation-operator", Version: "6.13.0", Locations: []types.Location{{StartLine: 2985, EndLine: 2988}}},
		{ID: "babel-plugin-syntax-export-extensions@6.13.0", Name: "babel-plugin-syntax-export-extensions", Version: "6.13.0", Locations: []types.Location{{StartLine: 2990, EndLine: 2993}}},
		{ID: "babel-plugin-syntax-flow@6.18.0", Name: "babel-plugin-syntax-flow", Version: "6.18.0", Locations: []types.Location{{StartLine: 2995, EndLine: 2998}}},
		{ID: "babel-plugin-syntax-jsx@6.18.0", Name: "babel-plugin-syntax-jsx", Version: "6.18.0", Locations: []types.Location{{StartLine: 3000, EndLine: 3003}}},
		{ID: "babel-plugin-syntax-object-rest-spread@6.13.0", Name: "babel-plugin-syntax-object-rest-spread", Version: "6.13.0", Locations: []types.Location{{StartLine: 3005, EndLine: 3008}}},
		{ID: "babel-plugin-syntax-trailing-function-commas@6.22.0", Name: "babel-plugin-syntax-trailing-function-commas", Version: "6.22.0", Locations: []types.Location{{StartLine: 3010, EndLine: 3013}}},
		{ID: "babel-plugin-transform-async-generator-functions@6.24.1", Name: "babel-plugin-transform-async-generator-functions", Version: "6.24.1", Locations: []types.Location{{StartLine: 3015, EndLine: 3022}}},
		{ID: "babel-plugin-transform-async-to-generator@6.24.1", Name: "babel-plugin-transform-async-to-generator", Version: "6.24.1", Locations: []types.Location{{StartLine: 3024, EndLine: 3031}}},
		{ID: "babel-plugin-transform-class-constructor-call@6.24.1", Name: "babel-plugin-transform-class-constructor-call", Version: "6.24.1", Locations: []types.Location{{StartLine: 3033, EndLine: 3040}}},
		{ID: "babel-plugin-transform-class-properties@6.24.1", Name: "babel-plugin-transform-class-properties", Version: "6.24.1", Locations: []types.Location{{StartLine: 3042, EndLine: 3050}}},
		{ID: "babel-plugin-transform-decorators@6.24.1", Name: "babel-plugin-transform-decorators", Version: "6.24.1", Locations: []types.Location{{StartLine: 3052, EndLine: 3061}}},
		{ID: "babel-plugin-transform-es2015-arrow-functions@6.22.0", Name: "babel-plugin-transform-es2015-arrow-functions", Version: "6.22.0", Locations: []types.Location{{StartLine: 3063, EndLine: 3068}}},
		{ID: "babel-plugin-transform-es2015-block-scoped-functions@6.22.0", Name: "babel-plugin-transform-es2015-block-scoped-functions", Version: "6.22.0", Locations: []types.Location{{StartLine: 3070, EndLine: 3075}}},
		{ID: "babel-plugin-transform-es2015-block-scoping@6.26.0", Name: "babel-plugin-transform-es2015-block-scoping", Version: "6.26.0", Locations: []types.Location{{StartLine: 3077, EndLine: 3086}}},
		{ID: "babel-plugin-transform-es2015-classes@6.24.1", Name: "babel-plugin-transform-es2015-classes", Version: "6.24.1", Locations: []types.Location{{StartLine: 3088, EndLine: 3101}}},
		{ID: "babel-plugin-transform-es2015-computed-properties@6.24.1", Name: "babel-plugin-transform-es2015-computed-properties", Version: "6.24.1", Locations: []types.Location{{StartLine: 3103, EndLine: 3109}}},
		{ID: "babel-plugin-transform-es2015-destructuring@6.23.0", Name: "babel-plugin-transform-es2015-destructuring", Version: "6.23.0", Locations: []types.Location{{StartLine: 3111, EndLine: 3116}}},
		{ID: "babel-plugin-transform-es2015-duplicate-keys@6.24.1", Name: "babel-plugin-transform-es2015-duplicate-keys", Version: "6.24.1", Locations: []types.Location{{StartLine: 3118, EndLine: 3124}}},
		{ID: "babel-plugin-transform-es2015-for-of@6.23.0", Name: "babel-plugin-transform-es2015-for-of", Version: "6.23.0", Locations: []types.Location{{StartLine: 3126, EndLine: 3131}}},
		{ID: "babel-plugin-transform-es2015-function-name@6.24.1", Name: "babel-plugin-transform-es2015-function-name", Version: "6.24.1", Locations: []types.Location{{StartLine: 3133, EndLine: 3140}}},
		{ID: "babel-plugin-transform-es2015-literals@6.22.0", Name: "babel-plugin-transform-es2015-literals", Version: "6.22.0", Locations: []types.Location{{StartLine: 3142, EndLine: 3147}}},
		{ID: "babel-plugin-transform-es2015-modules-amd@6.24.1", Name: "babel-plugin-transform-es2015-modules-amd", Version: "6.24.1", Locations: []types.Location{{StartLine: 3149, EndLine: 3156}}},
		{ID: "babel-plugin-transform-es2015-modules-commonjs@6.26.2", Name: "babel-plugin-transform-es2015-modules-commonjs", Version: "6.26.2", Locations: []types.Location{{StartLine: 3158, EndLine: 3166}}},
		{ID: "babel-plugin-transform-es2015-modules-systemjs@6.24.1", Name: "babel-plugin-transform-es2015-modules-systemjs", Version: "6.24.1", Locations: []types.Location{{StartLine: 3168, EndLine: 3175}}},
		{ID: "babel-plugin-transform-es2015-modules-umd@6.24.1", Name: "babel-plugin-transform-es2015-modules-umd", Version: "6.24.1", Locations: []types.Location{{StartLine: 3177, EndLine: 3184}}},
		{ID: "babel-plugin-transform-es2015-object-super@6.24.1", Name: "babel-plugin-transform-es2015-object-super", Version: "6.24.1", Locations: []types.Location{{StartLine: 3186, EndLine: 3192}}},
		{ID: "babel-plugin-transform-es2015-parameters@6.24.1", Name: "babel-plugin-transform-es2015-parameters", Version: "6.24.1", Locations: []types.Location{{StartLine: 3194, EndLine: 3204}}},
		{ID: "babel-plugin-transform-es2015-shorthand-properties@6.24.1", Name: "babel-plugin-transform-es2015-shorthand-properties", Version: "6.24.1", Locations: []types.Location{{StartLine: 3206, EndLine: 3212}}},
		{ID: "babel-plugin-transform-es2015-spread@6.22.0", Name: "babel-plugin-transform-es2015-spread", Version: "6.22.0", Locations: []types.Location{{StartLine: 3214, EndLine: 3219}}},
		{ID: "babel-plugin-transform-es2015-sticky-regex@6.24.1", Name: "babel-plugin-transform-es2015-sticky-regex", Version: "6.24.1", Locations: []types.Location{{StartLine: 3221, EndLine: 3228}}},
		{ID: "babel-plugin-transform-es2015-template-literals@6.22.0", Name: "babel-plugin-transform-es2015-template-literals", Version: "6.22.0", Locations: []types.Location{{StartLine: 3230, EndLine: 3235}}},
		{ID: "babel-plugin-transform-es2015-typeof-symbol@6.23.0", Name: "babel-plugin-transform-es2015-typeof-symbol", Version: "6.23.0", Locations: []types.Location{{StartLine: 3237, EndLine: 3242}}},
		{ID: "babel-plugin-transform-es2015-unicode-regex@6.24.1", Name: "babel-plugin-transform-es2015-unicode-regex", Version: "6.24.1", Locations: []types.Location{{StartLine: 3244, EndLine: 3251}}},
		{ID: "babel-plugin-transform-exponentiation-operator@6.24.1", Name: "babel-plugin-transform-exponentiation-operator", Version: "6.24.1", Locations: []types.Location{{StartLine: 3253, EndLine: 3260}}},
		{ID: "babel-plugin-transform-export-extensions@6.22.0", Name: "babel-plugin-transform-export-extensions", Version: "6.22.0", Locations: []types.Location{{StartLine: 3262, EndLine: 3268}}},
		{ID: "babel-plugin-transform-flow-strip-types@6.22.0", Name: "babel-plugin-transform-flow-strip-types", Version: "6.22.0", Locations: []types.Location{{StartLine: 3270, EndLine: 3276}}},
		{ID: "babel-plugin-transform-inline-consecutive-adds@0.4.3", Name: "babel-plugin-transform-inline-consecutive-adds", Version: "0.4.3", Locations: []types.Location{{StartLine: 3278, EndLine: 3281}}},
		{ID: "babel-plugin-transform-member-expression-literals@6.9.4", Name: "babel-plugin-transform-member-expression-literals", Version: "6.9.4", Locations: []types.Location{{StartLine: 3283, EndLine: 3286}}},
		{ID: "babel-plugin-transform-merge-sibling-variables@6.9.4", Name: "babel-plugin-transform-merge-sibling-variables", Version: "6.9.4", Locations: []types.Location{{StartLine: 3288, EndLine: 3291}}},
		{ID: "babel-plugin-transform-minify-booleans@6.9.4", Name: "babel-plugin-transform-minify-booleans", Version: "6.9.4", Locations: []types.Location{{StartLine: 3293, EndLine: 3296}}},
		{ID: "babel-plugin-transform-object-rest-spread@6.26.0", Name: "babel-plugin-transform-object-rest-spread", Version: "6.26.0", Locations: []types.Location{{StartLine: 3298, EndLine: 3304}}},
		{ID: "babel-plugin-transform-property-literals@6.9.4", Name: "babel-plugin-transform-property-literals", Version: "6.9.4", Locations: []types.Location{{StartLine: 3306, EndLine: 3311}}},
		{ID: "babel-plugin-transform-react-display-name@6.25.0", Name: "babel-plugin-transform-react-display-name", Version: "6.25.0", Locations: []types.Location{{StartLine: 3313, EndLine: 3318}}},
		{ID: "babel-plugin-transform-react-jsx-self@6.22.0", Name: "babel-plugin-transform-react-jsx-self", Version: "6.22.0", Locations: []types.Location{{StartLine: 3320, EndLine: 3326}}},
		{ID: "babel-plugin-transform-react-jsx-source@6.22.0", Name: "babel-plugin-transform-react-jsx-source", Version: "6.22.0", Locations: []types.Location{{StartLine: 3328, EndLine: 3334}}},
		{ID: "babel-plugin-transform-react-jsx@6.24.1", Name: "babel-plugin-transform-react-jsx", Version: "6.24.1", Locations: []types.Location{{StartLine: 3336, EndLine: 3343}}},
		{ID: "babel-plugin-transform-react-remove-prop-types@0.4.18", Name: "babel-plugin-transform-react-remove-prop-types", Version: "0.4.18", Locations: []types.Location{{StartLine: 3345, EndLine: 3348}}},
		{ID: "babel-plugin-transform-regenerator@6.26.0", Name: "babel-plugin-transform-regenerator", Version: "6.26.0", Locations: []types.Location{{StartLine: 3350, EndLine: 3355}}},
		{ID: "babel-plugin-transform-regexp-constructors@0.4.3", Name: "babel-plugin-transform-regexp-constructors", Version: "0.4.3", Locations: []types.Location{{StartLine: 3357, EndLine: 3360}}},
		{ID: "babel-plugin-transform-remove-console@6.9.4", Name: "babel-plugin-transform-remove-console", Version: "6.9.4", Locations: []types.Location{{StartLine: 3362, EndLine: 3365}}},
		{ID: "babel-plugin-transform-remove-debugger@6.9.4", Name: "babel-plugin-transform-remove-debugger", Version: "6.9.4", Locations: []types.Location{{StartLine: 3367, EndLine: 3370}}},
		{ID: "babel-plugin-transform-remove-undefined@0.5.0", Name: "babel-plugin-transform-remove-undefined", Version: "0.5.0", Locations: []types.Location{{StartLine: 3372, EndLine: 3377}}},
		{ID: "babel-plugin-transform-runtime@6.23.0", Name: "babel-plugin-transform-runtime", Version: "6.23.0", Locations: []types.Location{{StartLine: 3379, EndLine: 3384}}},
		{ID: "babel-plugin-transform-simplify-comparison-operators@6.9.4", Name: "babel-plugin-transform-simplify-comparison-operators", Version: "6.9.4", Locations: []types.Location{{StartLine: 3386, EndLine: 3389}}},
		{ID: "babel-plugin-transform-strict-mode@6.24.1", Name: "babel-plugin-transform-strict-mode", Version: "6.24.1", Locations: []types.Location{{StartLine: 3391, EndLine: 3397}}},
		{ID: "babel-plugin-transform-undefined-to-void@6.9.4", Name: "babel-plugin-transform-undefined-to-void", Version: "6.9.4", Locations: []types.Location{{StartLine: 3399, EndLine: 3402}}},
		{ID: "babel-polyfill@6.26.0", Name: "babel-polyfill", Version: "6.26.0", Locations: []types.Location{{StartLine: 3404, EndLine: 3411}}},
		{ID: "babel-preset-env@1.7.0", Name: "babel-preset-env", Version: "1.7.0", Locations: []types.Location{{StartLine: 3413, EndLine: 3447}}},
		{ID: "babel-preset-es2015@6.24.1", Name: "babel-preset-es2015", Version: "6.24.1", Locations: []types.Location{{StartLine: 3449, EndLine: 3477}}},
		{ID: "babel-preset-flow@6.23.0", Name: "babel-preset-flow", Version: "6.23.0", Locations: []types.Location{{StartLine: 3479, EndLine: 3484}}},
		{ID: "babel-preset-jest@23.2.0", Name: "babel-preset-jest", Version: "23.2.0", Locations: []types.Location{{StartLine: 3486, EndLine: 3492}}},
		{ID: "babel-preset-minify@0.5.0", Name: "babel-preset-minify", Version: "0.5.0", Locations: []types.Location{{StartLine: 3494, EndLine: 3521}}},
		{ID: "babel-preset-react-app@6.1.0", Name: "babel-preset-react-app", Version: "6.1.0", Locations: []types.Location{{StartLine: 3523, EndLine: 3546}}},
		{ID: "babel-preset-react@6.24.1", Name: "babel-preset-react", Version: "6.24.1", Locations: []types.Location{{StartLine: 3548, EndLine: 3558}}},
		{ID: "babel-preset-stage-1@6.24.1", Name: "babel-preset-stage-1", Version: "6.24.1", Locations: []types.Location{{StartLine: 3560, EndLine: 3567}}},
		{ID: "babel-preset-stage-2@6.24.1", Name: "babel-preset-stage-2", Version: "6.24.1", Locations: []types.Location{{StartLine: 3569, EndLine: 3577}}},
		{ID: "babel-preset-stage-3@6.24.1", Name: "babel-preset-stage-3", Version: "6.24.1", Locations: []types.Location{{StartLine: 3579, EndLine: 3588}}},
		{ID: "babel-register@6.26.0", Name: "babel-register", Version: "6.26.0", Locations: []types.Location{{StartLine: 3590, EndLine: 3601}}},
		{ID: "babel-runtime@6.26.0", Name: "babel-runtime", Version: "6.26.0", Locations: []types.Location{{StartLine: 3603, EndLine: 3609}}},
		{ID: "babel-standalone@6.26.0", Name: "babel-standalone", Version: "6.26.0", Locations: []types.Location{{StartLine: 3611, EndLine: 3614}}},
		{ID: "babel-template@6.26.0", Name: "babel-template", Version: "6.26.0", Locations: []types.Location{{StartLine: 3616, EndLine: 3625}}},
		{ID: "babel-traverse@6.26.0", Name: "babel-traverse", Version: "6.26.0", Locations: []types.Location{{StartLine: 3627, EndLine: 3640}}},
		{ID: "babel-types@6.26.0", Name: "babel-types", Version: "6.26.0", Locations: []types.Location{{StartLine: 3642, EndLine: 3650}}},
		{ID: "babylon@7.0.0-beta.44", Name: "babylon", Version: "7.0.0-beta.44", Locations: []types.Location{{StartLine: 3652, EndLine: 3655}}},
		{ID: "babylon@6.18.0", Name: "babylon", Version: "6.18.0", Locations: []types.Location{{StartLine: 3657, EndLine: 3660}}},
		{ID: "babylon@7.0.0-beta.47", Name: "babylon", Version: "7.0.0-beta.47", Locations: []types.Location{{StartLine: 3662, EndLine: 3665}}},
		{ID: "backo2@1.0.2", Name: "backo2", Version: "1.0.2", Locations: []types.Location{{StartLine: 3667, EndLine: 3670}}},
		{ID: "bail@1.0.4", Name: "bail", Version: "1.0.4", Locations: []types.Location{{StartLine: 3672, EndLine: 3675}}},
		{ID: "balanced-match@1.0.0", Name: "balanced-match", Version: "1.0.0", Locations: []types.Location{{StartLine: 3677, EndLine: 3680}}},
		{ID: "base64-arraybuffer@0.1.5", Name: "base64-arraybuffer", Version: "0.1.5", Locations: []types.Location{{StartLine: 3682, EndLine: 3685}}},
		{ID: "base64-js@1.3.0", Name: "base64-js", Version: "1.3.0", Locations: []types.Location{{StartLine: 3687, EndLine: 3690}}},
		{ID: "base64id@1.0.0", Name: "base64id", Version: "1.0.0", Locations: []types.Location{{StartLine: 3692, EndLine: 3695}}},
		{ID: "base@0.11.2", Name: "base", Version: "0.11.2", Locations: []types.Location{{StartLine: 3697, EndLine: 3708}}},
		{ID: "batch@0.6.1", Name: "batch", Version: "0.6.1", Locations: []types.Location{{StartLine: 3710, EndLine: 3713}}},
		{ID: "bcrypt-pbkdf@1.0.2", Name: "bcrypt-pbkdf", Version: "1.0.2", Locations: []types.Location{{StartLine: 3715, EndLine: 3720}}},
		{ID: "before-after-hook@1.4.0", Name: "before-after-hook", Version: "1.4.0", Locations: []types.Location{{StartLine: 3722, EndLine: 3725}}},
		{ID: "better-assert@1.0.2", Name: "better-assert", Version: "1.0.2", Locations: []types.Location{{StartLine: 3727, EndLine: 3732}}},
		{ID: "bfj@6.1.1", Name: "bfj", Version: "6.1.1", Locations: []types.Location{{StartLine: 3734, EndLine: 3742}}},
		{ID: "big-integer@1.6.43", Name: "big-integer", Version: "1.6.43", Locations: []types.Location{{StartLine: 3744, EndLine: 3747}}},
		{ID: "big.js@3.2.0", Name: "big.js", Version: "3.2.0", Locations: []types.Location{{StartLine: 3749, EndLine: 3752}}},
		{ID: "big.js@5.2.2", Name: "big.js", Version: "5.2.2", Locations: []types.Location{{StartLine: 3754, EndLine: 3757}}},
		{ID: "bin-links@1.1.2", Name: "bin-links", Version: "1.1.2", Locations: []types.Location{{StartLine: 3759, EndLine: 3768}}},
		{ID: "binary-extensions@1.13.1", Name: "binary-extensions", Version: "1.13.1", Locations: []types.Location{{StartLine: 3770, EndLine: 3773}}},
		{ID: "binary@0.3.0", Name: "binary", Version: "0.3.0", Locations: []types.Location{{StartLine: 3775, EndLine: 3781}}},
		{ID: "blob@0.0.5", Name: "blob", Version: "0.0.5", Locations: []types.Location{{StartLine: 3783, EndLine: 3786}}},
		{ID: "block-stream@0.0.9", Name: "block-stream", Version: "0.0.9", Locations: []types.Location{{StartLine: 3788, EndLine: 3793}}},
		{ID: "bluebird@3.5.4", Name: "bluebird", Version: "3.5.4", Locations: []types.Location{{StartLine: 3795, EndLine: 3798}}},
		{ID: "bluebird@3.4.7", Name: "bluebird", Version: "3.4.7", Locations: []types.Location{{StartLine: 3800, EndLine: 3803}}},
		{ID: "bn.js@4.11.8", Name: "bn.js", Version: "4.11.8", Locations: []types.Location{{StartLine: 3805, EndLine: 3808}}},
		{ID: "body-parser@1.18.3", Name: "body-parser", Version: "1.18.3", Locations: []types.Location{{StartLine: 3810, EndLine: 3824}}},
		{ID: "bonjour@3.5.0", Name: "bonjour", Version: "3.5.0", Locations: []types.Location{{StartLine: 3826, EndLine: 3836}}},
		{ID: "boolbase@1.0.0", Name: "boolbase", Version: "1.0.0", Locations: []types.Location{{StartLine: 3838, EndLine: 3841}}},
		{ID: "boxen@1.3.0", Name: "boxen", Version: "1.3.0", Locations: []types.Location{{StartLine: 3843, EndLine: 3854}}},
		{ID: "boxen@2.1.0", Name: "boxen", Version: "2.1.0", Locations: []types.Location{{StartLine: 3856, EndLine: 3867}}},
		{ID: "brace-expansion@1.1.11", Name: "brace-expansion", Version: "1.1.11", Locations: []types.Location{{StartLine: 3869, EndLine: 3875}}},
		{ID: "braces@1.8.5", Name: "braces", Version: "1.8.5", Locations: []types.Location{{StartLine: 3877, EndLine: 3884}}},
		{ID: "braces@2.3.2", Name: "braces", Version: "2.3.2", Locations: []types.Location{{StartLine: 3886, EndLine: 3900}}},
		{ID: "brcast@3.0.1", Name: "brcast", Version: "3.0.1", Locations: []types.Location{{StartLine: 3902, EndLine: 3905}}},
		{ID: "brorand@1.1.0", Name: "brorand", Version: "1.1.0", Locations: []types.Location{{StartLine: 3907, EndLine: 3910}}},
		{ID: "browser-process-hrtime@0.1.3", Name: "browser-process-hrtime", Version: "0.1.3", Locations: []types.Location{{StartLine: 3912, EndLine: 3915}}},
		{ID: "browser-resolve@1.11.3", Name: "browser-resolve", Version: "1.11.3", Locations: []types.Location{{StartLine: 3917, EndLine: 3922}}},
		{ID: "browserify-aes@1.2.0", Name: "browserify-aes", Version: "1.2.0", Locations: []types.Location{{StartLine: 3924, EndLine: 3934}}},
		{ID: "browserify-cipher@1.0.1", Name: "browserify-cipher", Version: "1.0.1", Locations: []types.Location{{StartLine: 3936, EndLine: 3943}}},
		{ID: "browserify-des@1.0.2", Name: "browserify-des", Version: "1.0.2", Locations: []types.Location{{StartLine: 3945, EndLine: 3953}}},
		{ID: "browserify-rsa@4.0.1", Name: "browserify-rsa", Version: "4.0.1", Locations: []types.Location{{StartLine: 3955, EndLine: 3961}}},
		{ID: "browserify-sign@4.0.4", Name: "browserify-sign", Version: "4.0.4", Locations: []types.Location{{StartLine: 3963, EndLine: 3974}}},
		{ID: "browserify-zlib@0.2.0", Name: "browserify-zlib", Version: "0.2.0", Locations: []types.Location{{StartLine: 3976, EndLine: 3981}}},
		{ID: "browserslist@4.1.1", Name: "browserslist", Version: "4.1.1", Locations: []types.Location{{StartLine: 3983, EndLine: 3990}}},
		{ID: "browserslist@3.2.8", Name: "browserslist", Version: "3.2.8", Locations: []types.Location{{StartLine: 3992, EndLine: 3998}}},
		{ID: "browserslist@4.6.0", Name: "browserslist", Version: "4.6.0", Locations: []types.Location{{StartLine: 4000, EndLine: 4007}}},
		{ID: "bser@2.0.0", Name: "bser", Version: "2.0.0", Locations: []types.Location{{StartLine: 4009, EndLine: 4014}}},
		{ID: "btoa-lite@1.0.0", Name: "btoa-lite", Version: "1.0.0", Locations: []types.Location{{StartLine: 4016, EndLine: 4019}}},
		{ID: "buffer-from@1.1.1", Name: "buffer-from", Version: "1.1.1", Locations: []types.Location{{StartLine: 4021, EndLine: 4024}}},
		{ID: "buffer-indexof-polyfill@1.0.1", Name: "buffer-indexof-polyfill", Version: "1.0.1", Locations: []types.Location{{StartLine: 4026, EndLine: 4029}}},
		{ID: "buffer-indexof@1.1.1", Name: "buffer-indexof", Version: "1.1.1", Locations: []types.Location{{StartLine: 4031, EndLine: 4034}}},
		{ID: "buffer-shims@1.0.0", Name: "buffer-shims", Version: "1.0.0", Locations: []types.Location{{StartLine: 4036, EndLine: 4039}}},
		{ID: "buffer-xor@1.0.3", Name: "buffer-xor", Version: "1.0.3", Locations: []types.Location{{StartLine: 4041, EndLine: 4044}}},
		{ID: "buffer@4.9.1", Name: "buffer", Version: "4.9.1", Locations: []types.Location{{StartLine: 4046, EndLine: 4053}}},
		{ID: "buffers@0.1.1", Name: "buffers", Version: "0.1.1", Locations: []types.Location{{StartLine: 4055, EndLine: 4058}}},
		{ID: "builtin-status-codes@3.0.0", Name: "builtin-status-codes", Version: "3.0.0", Locations: []types.Location{{StartLine: 4060, EndLine: 4063}}},
		{ID: "builtins@1.0.3", Name: "builtins", Version: "1.0.3", Locations: []types.Location{{StartLine: 4065, EndLine: 4068}}},
		{ID: "byline@5.0.0", Name: "byline", Version: "5.0.0", Locations: []types.Location{{StartLine: 4070, EndLine: 4073}}},
		{ID: "byte-size@5.0.1", Name: "byte-size", Version: "5.0.1", Locations: []types.Location{{StartLine: 4075, EndLine: 4078}}},
		{ID: "bytes@3.0.0", Name: "bytes", Version: "3.0.0", Locations: []types.Location{{StartLine: 4080, EndLine: 4083}}},
		{ID: "cacache@10.0.4", Name: "cacache", Version: "10.0.4", Locations: []types.Location{{StartLine: 4085, EndLine: 4102}}},
		{ID: "cacache@11.3.2", Name: "cacache", Version: "11.3.2", Locations: []types.Location{{StartLine: 4104, EndLine: 4122}}},
		{ID: "cache-base@1.0.1", Name: "cache-base", Version: "1.0.1", Locations: []types.Location{{StartLine: 4124, EndLine: 4137}}},
		{ID: "cache-loader@1.2.5", Name: "cache-loader", Version: "1.2.5", Locations: []types.Location{{StartLine: 4139, EndLine: 4147}}},
		{ID: "call-limit@1.1.0", Name: "call-limit", Version: "1.1.0", Locations: []types.Location{{StartLine: 4149, EndLine: 4152}}},
		{ID: "call-me-maybe@1.0.1", Name: "call-me-maybe", Version: "1.0.1", Locations: []types.Location{{StartLine: 4154, EndLine: 4157}}},
		{ID: "caller-callsite@2.0.0", Name: "caller-callsite", Version: "2.0.0", Locations: []types.Location{{StartLine: 4159, EndLine: 4164}}},
		{ID: "caller-path@2.0.0", Name: "caller-path", Version: "2.0.0", Locations: []types.Location{{StartLine: 4166, EndLine: 4171}}},
		{ID: "callsite@1.0.0", Name: "callsite", Version: "1.0.0", Locations: []types.Location{{StartLine: 4173, EndLine: 4176}}},
		{ID: "callsites@2.0.0", Name: "callsites", Version: "2.0.0", Locations: []types.Location{{StartLine: 4178, EndLine: 4181}}},
		{ID: "callsites@3.1.0", Name: "callsites", Version: "3.1.0", Locations: []types.Location{{StartLine: 4183, EndLine: 4186}}},
		{ID: "camel-case@3.0.0", Name: "camel-case", Version: "3.0.0", Locations: []types.Location{{StartLine: 4188, EndLine: 4194}}},
		{ID: "camelcase@3.0.0", Name: "camelcase", Version: "3.0.0", Locations: []types.Location{{StartLine: 4196, EndLine: 4199}}},
		{ID: "camelcase@4.1.0", Name: "camelcase", Version: "4.1.0", Locations: []types.Location{{StartLine: 4201, EndLine: 4204}}},
		{ID: "camelcase@5.3.1", Name: "camelcase", Version: "5.3.1", Locations: []types.Location{{StartLine: 4206, EndLine: 4209}}},
		{ID: "camelize@1.0.0", Name: "camelize", Version: "1.0.0", Locations: []types.Location{{StartLine: 4211, EndLine: 4214}}},
		{ID: "caniuse-lite@1.0.30000967", Name: "caniuse-lite", Version: "1.0.30000967", Locations: []types.Location{{StartLine: 4216, EndLine: 4219}}},
		{ID: "capture-exit@1.2.0", Name: "capture-exit", Version: "1.2.0", Locations: []types.Location{{StartLine: 4221, EndLine: 4226}}},
		{ID: "capture-stack-trace@1.0.1", Name: "capture-stack-trace", Version: "1.0.1", Locations: []types.Location{{StartLine: 4228, EndLine: 4231}}},
		{ID: "case-sensitive-paths-webpack-plugin@2.2.0", Name: "case-sensitive-paths-webpack-plugin", Version: "2.2.0", Locations: []types.Location{{StartLine: 4233, EndLine: 4236}}},
		{ID: "caseless@0.12.0", Name: "caseless", Version: "0.12.0", Locations: []types.Location{{StartLine: 4238, EndLine: 4241}}},
		{ID: "ccount@1.0.4", Name: "ccount", Version: "1.0.4", Locations: []types.Location{{StartLine: 4243, EndLine: 4246}}},
		{ID: "chainsaw@0.1.0", Name: "chainsaw", Version: "0.1.0", Locations: []types.Location{{StartLine: 4248, EndLine: 4253}}},
		{ID: "chalk@2.4.1", Name: "chalk", Version: "2.4.1", Locations: []types.Location{{StartLine: 4255, EndLine: 4262}}},
		{ID: "chalk@1.1.3", Name: "chalk", Version: "1.1.3", Locations: []types.Location{{StartLine: 4264, EndLine: 4273}}},
		{ID: "chalk@2.4.2", Name: "chalk", Version: "2.4.2", Locations: []types.Location{{StartLine: 4275, EndLine: 4282}}},
		{ID: "chalk@0.4.0", Name: "chalk", Version: "0.4.0", Locations: []types.Location{{StartLine: 4284, EndLine: 4291}}},
		{ID: "change-emitter@0.1.6", Name: "change-emitter", Version: "0.1.6", Locations: []types.Location{{StartLine: 4293, EndLine: 4296}}},
		{ID: "chardet@0.7.0", Name: "chardet", Version: "0.7.0", Locations: []types.Location{{StartLine: 4298, EndLine: 4301}}},
		{ID: "charenc@0.0.2", Name: "charenc", Version: "0.0.2", Locations: []types.Location{{StartLine: 4303, EndLine: 4306}}},
		{ID: "check-types@7.4.0", Name: "check-types", Version: "7.4.0", Locations: []types.Location{{StartLine: 4308, EndLine: 4311}}},
		{ID: "cheerio@1.0.0-rc.3", Name: "cheerio", Version: "1.0.0-rc.3", Locations: []types.Location{{StartLine: 4313, EndLine: 4323}}},
		{ID: "child-process-promise@2.2.1", Name: "child-process-promise", Version: "2.2.1", Locations: []types.Location{{StartLine: 4325, EndLine: 4332}}},
		{ID: "chokidar@1.7.0", Name: "chokidar", Version: "1.7.0", Locations: []types.Location{{StartLine: 4334, EndLine: 4348}}},
		{ID: "chokidar@2.1.5", Name: "chokidar", Version: "2.1.5", Locations: []types.Location{{StartLine: 4350, EndLine: 4367}}},
		{ID: "chownr@1.1.1", Name: "chownr", Version: "1.1.1", Locations: []types.Location{{StartLine: 4369, EndLine: 4372}}},
		{ID: "chrome-trace-event@1.0.0", Name: "chrome-trace-event", Version: "1.0.0", Locations: []types.Location{{StartLine: 4374, EndLine: 4379}}},
		{ID: "ci-info@1.6.0", Name: "ci-info", Version: "1.6.0", Locations: []types.Location{{StartLine: 4381, EndLine: 4384}}},
		{ID: "ci-info@2.0.0", Name: "ci-info", Version: "2.0.0", Locations: []types.Location{{StartLine: 4386, EndLine: 4389}}},
		{ID: "cidr-regex@2.0.10", Name: "cidr-regex", Version: "2.0.10", Locations: []types.Location{{StartLine: 4391, EndLine: 4396}}},
		{ID: "cipher-base@1.0.4", Name: "cipher-base", Version: "1.0.4", Locations: []types.Location{{StartLine: 4398, EndLine: 4404}}},
		{ID: "class-utils@0.3.6", Name: "class-utils", Version: "0.3.6", Locations: []types.Location{{StartLine: 4406, EndLine: 4414}}},
		{ID: "classnames@2.2.6", Name: "classnames", Version: "2.2.6", Locations: []types.Location{{StartLine: 4416, EndLine: 4419}}},
		{ID: "clean-css@4.2.1", Name: "clean-css", Version: "4.2.1", Locations: []types.Location{{StartLine: 4421, EndLine: 4426}}},
		{ID: "clean-webpack-plugin@0.1.19", Name: "clean-webpack-plugin", Version: "0.1.19", Locations: []types.Location{{StartLine: 4428, EndLine: 4433}}},
		{ID: "cli-boxes@1.0.0", Name: "cli-boxes", Version: "1.0.0", Locations: []types.Location{{StartLine: 4435, EndLine: 4438}}},
		{ID: "cli-columns@3.1.2", Name: "cli-columns", Version: "3.1.2", Locations: []types.Location{{StartLine: 4440, EndLine: 4446}}},
		{ID: "cli-cursor@1.0.2", Name: "cli-cursor", Version: "1.0.2", Locations: []types.Location{{StartLine: 4448, EndLine: 4453}}},
		{ID: "cli-cursor@2.1.0", Name: "cli-cursor", Version: "2.1.0", Locations: []types.Location{{StartLine: 4455, EndLine: 4460}}},
		{ID: "cli-table3@0.5.1", Name: "cli-table3", Version: "0.5.1", Locations: []types.Location{{StartLine: 4462, EndLine: 4470}}},
		{ID: "cli-truncate@0.2.1", Name: "cli-truncate", Version: "0.2.1", Locations: []types.Location{{StartLine: 4472, EndLine: 4478}}},
		{ID: "cli-width@1.1.1", Name: "cli-width", Version: "1.1.1", Locations: []types.Location{{StartLine: 4480, EndLine: 4483}}},
		{ID: "cli-width@2.2.0", Name: "cli-width", Version: "2.2.0", Locations: []types.Location{{StartLine: 4485, EndLine: 4488}}},
		{ID: "cliui@3.2.0", Name: "cliui", Version: "3.2.0", Locations: []types.Location{{StartLine: 4490, EndLine: 4497}}},
		{ID: "cliui@4.1.0", Name: "cliui", Version: "4.1.0", Locations: []types.Location{{StartLine: 4499, EndLine: 4506}}},
		{ID: "clone-deep@0.2.4", Name: "clone-deep", Version: "0.2.4", Locations: []types.Location{{StartLine: 4508, EndLine: 4517}}},
		{ID: "clone@1.0.4", Name: "clone", Version: "1.0.4", Locations: []types.Location{{StartLine: 4519, EndLine: 4522}}},
		{ID: "clsx@1.0.4", Name: "clsx", Version: "1.0.4", Locations: []types.Location{{StartLine: 4524, EndLine: 4527}}},
		{ID: "cmd-shim@2.0.2", Name: "cmd-shim", Version: "2.0.2", Locations: []types.Location{{StartLine: 4529, EndLine: 4535}}},
		{ID: "co@4.6.0", Name: "co", Version: "4.6.0", Locations: []types.Location{{StartLine: 4537, EndLine: 4540}}},
		{ID: "coa@2.0.2", Name: "coa", Version: "2.0.2", Locations: []types.Location{{StartLine: 4542, EndLine: 4549}}},
		{ID: "code-point-at@1.1.0", Name: "code-point-at", Version: "1.1.0", Locations: []types.Location{{StartLine: 4551, EndLine: 4554}}},
		{ID: "collection-visit@1.0.0", Name: "collection-visit", Version: "1.0.0", Locations: []types.Location{{StartLine: 4556, EndLine: 4562}}},
		{ID: "color-convert@1.9.3", Name: "color-convert", Version: "1.9.3", Locations: []types.Location{{StartLine: 4564, EndLine: 4569}}},
		{ID: "color-name@1.1.3", Name: "color-name", Version: "1.1.3", Locations: []types.Location{{StartLine: 4571, EndLine: 4574}}},
		{ID: "colors@1.3.3", Name: "colors", Version: "1.3.3", Locations: []types.Location{{StartLine: 4576, EndLine: 4579}}},
		{ID: "columnify@1.5.4", Name: "columnify", Version: "1.5.4", Locations: []types.Location{{StartLine: 4581, EndLine: 4587}}},
		{ID: "combined-stream@1.0.8", Name: "combined-stream", Version: "1.0.8", Locations: []types.Location{{StartLine: 4589, EndLine: 4594}}},
		{ID: "comma-separated-tokens@1.0.7", Name: "comma-separated-tokens", Version: "1.0.7", Locations: []types.Location{{StartLine: 4596, EndLine: 4599}}},
		{ID: "commander@2.17.1", Name: "commander", Version: "2.17.1", Locations: []types.Location{{StartLine: 4601, EndLine: 4604}}},
		{ID: "commander@2.20.0", Name: "commander", Version: "2.20.0", Locations: []types.Location{{StartLine: 4606, EndLine: 4609}}},
		{ID: "commander@2.19.0", Name: "commander", Version: "2.19.0", Locations: []types.Location{{StartLine: 4611, EndLine: 4614}}},
		{ID: "common-tags@1.8.0", Name: "common-tags", Version: "1.8.0", Locations: []types.Location{{StartLine: 4616, EndLine: 4619}}},
		{ID: "commondir@1.0.1", Name: "commondir", Version: "1.0.1", Locations: []types.Location{{StartLine: 4621, EndLine: 4624}}},
		{ID: "component-bind@1.0.0", Name: "component-bind", Version: "1.0.0", Locations: []types.Location{{StartLine: 4626, EndLine: 4629}}},
		{ID: "component-emitter@1.2.1", Name: "component-emitter", Version: "1.2.1", Locations: []types.Location{{StartLine: 4631, EndLine: 4634}}},
		{ID: "component-emitter@1.3.0", Name: "component-emitter", Version: "1.3.0", Locations: []types.Location{{StartLine: 4636, EndLine: 4639}}},
		{ID: "component-inherit@0.0.3", Name: "component-inherit", Version: "0.0.3", Locations: []types.Location{{StartLine: 4641, EndLine: 4644}}},
		{ID: "compressible@2.0.17", Name: "compressible", Version: "2.0.17", Locations: []types.Location{{StartLine: 4646, EndLine: 4651}}},
		{ID: "compression@1.7.4", Name: "compression", Version: "1.7.4", Locations: []types.Location{{StartLine: 4653, EndLine: 4664}}},
		{ID: "concat-map@0.0.1", Name: "concat-map", Version: "0.0.1", Locations: []types.Location{{StartLine: 4666, EndLine: 4669}}},
		{ID: "concat-stream@1.6.2", Name: "concat-stream", Version: "1.6.2", Locations: []types.Location{{StartLine: 4671, EndLine: 4679}}},
		{ID: "config-chain@1.1.12", Name: "config-chain", Version: "1.1.12", Locations: []types.Location{{StartLine: 4681, EndLine: 4687}}},
		{ID: "configstore@3.1.2", Name: "configstore", Version: "3.1.2", Locations: []types.Location{{StartLine: 4689, EndLine: 4699}}},
		{ID: "connect-history-api-fallback@1.6.0", Name: "connect-history-api-fallback", Version: "1.6.0", Locations: []types.Location{{StartLine: 4701, EndLine: 4704}}},
		{ID: "console-browserify@1.1.0", Name: "console-browserify", Version: "1.1.0", Locations: []types.Location{{StartLine: 4706, EndLine: 4711}}},
		{ID: "console-control-strings@1.1.0", Name: "console-control-strings", Version: "1.1.0", Locations: []types.Location{{StartLine: 4713, EndLine: 4716}}},
		{ID: "console-polyfill@0.3.0", Name: "console-polyfill", Version: "0.3.0", Locations: []types.Location{{StartLine: 4718, EndLine: 4721}}},
		{ID: "constants-browserify@1.0.0", Name: "constants-browserify", Version: "1.0.0", Locations: []types.Location{{StartLine: 4723, EndLine: 4726}}},
		{ID: "contains-path@0.1.0", Name: "contains-path", Version: "0.1.0", Locations: []types.Location{{StartLine: 4728, EndLine: 4731}}},
		{ID: "content-disposition@0.5.2", Name: "content-disposition", Version: "0.5.2", Locations: []types.Location{{StartLine: 4733, EndLine: 4736}}},
		{ID: "content-type@1.0.4", Name: "content-type", Version: "1.0.4", Locations: []types.Location{{StartLine: 4738, EndLine: 4741}}},
		{ID: "convert-source-map@1.6.0", Name: "convert-source-map", Version: "1.6.0", Locations: []types.Location{{StartLine: 4743, EndLine: 4748}}},
		{ID: "cookie-signature@1.0.6", Name: "cookie-signature", Version: "1.0.6", Locations: []types.Location{{StartLine: 4750, EndLine: 4753}}},
		{ID: "cookie@0.3.1", Name: "cookie", Version: "0.3.1", Locations: []types.Location{{StartLine: 4755, EndLine: 4758}}},
		{ID: "copy-concurrently@1.0.5", Name: "copy-concurrently", Version: "1.0.5", Locations: []types.Location{{StartLine: 4760, EndLine: 4770}}},
		{ID: "copy-descriptor@0.1.1", Name: "copy-descriptor", Version: "0.1.1", Locations: []types.Location{{StartLine: 4772, EndLine: 4775}}},
		{ID: "copy-to-clipboard@3.2.0", Name: "copy-to-clipboard", Version: "3.2.0", Locations: []types.Location{{StartLine: 4777, EndLine: 4782}}},
		{ID: "copy-webpack-plugin@4.6.0", Name: "copy-webpack-plugin", Version: "4.6.0", Locations: []types.Location{{StartLine: 4784, EndLine: 4796}}},
		{ID: "core-js-compat@3.0.1", Name: "core-js-compat", Version: "3.0.1", Locations: []types.Location{{StartLine: 4798, EndLine: 4806}}},
		{ID: "core-js-pure@3.0.1", Name: "core-js-pure", Version: "3.0.1", Locations: []types.Location{{StartLine: 4808, EndLine: 4811}}},
		{ID: "core-js@3.0.1", Name: "core-js", Version: "3.0.1", Locations: []types.Location{{StartLine: 4813, EndLine: 4816}}},
		{ID: "core-js@1.2.7", Name: "core-js", Version: "1.2.7", Locations: []types.Location{{StartLine: 4818, EndLine: 4821}}},
		{ID: "core-js@2.6.5", Name: "core-js", Version: "2.6.5", Locations: []types.Location{{StartLine: 4823, EndLine: 4826}}},
		{ID: "core-util-is@1.0.2", Name: "core-util-is", Version: "1.0.2", Locations: []types.Location{{StartLine: 4828, EndLine: 4831}}},
		{ID: "cosmiconfig@4.0.0", Name: "cosmiconfig", Version: "4.0.0", Locations: []types.Location{{StartLine: 4833, EndLine: 4841}}},
		{ID: "cosmiconfig@5.2.1", Name: "cosmiconfig", Version: "5.2.1", Locations: []types.Location{{StartLine: 4843, EndLine: 4851}}},
		{ID: "create-ecdh@4.0.3", Name: "create-ecdh", Version: "4.0.3", Locations: []types.Location{{StartLine: 4853, EndLine: 4859}}},
		{ID: "create-error-class@3.0.2", Name: "create-error-class", Version: "3.0.2", Locations: []types.Location{{StartLine: 4861, EndLine: 4866}}},
		{ID: "create-hash@1.2.0", Name: "create-hash", Version: "1.2.0", Locations: []types.Location{{StartLine: 4868, EndLine: 4877}}},
		{ID: "create-hmac@1.1.7", Name: "create-hmac", Version: "1.1.7", Locations: []types.Location{{StartLine: 4879, EndLine: 4889}}},
		{ID: "create-react-class@15.6.3", Name: "create-react-class", Version: "15.6.3", Locations: []types.Location{{StartLine: 4891, EndLine: 4898}}},
		{ID: "create-react-context@0.2.2", Name: "create-react-context", Version: "0.2.2", Locations: []types.Location{{StartLine: 4900, EndLine: 4906}}},
		{ID: "create-react-context@0.2.3", Name: "create-react-context", Version: "0.2.3", Locations: []types.Location{{StartLine: 4908, EndLine: 4914}}},
		{ID: "cross-spawn@6.0.5", Name: "cross-spawn", Version: "6.0.5", Locations: []types.Location{{StartLine: 4916, EndLine: 4925}}},
		{ID: "cross-spawn@4.0.2", Name: "cross-spawn", Version: "4.0.2", Locations: []types.Location{{StartLine: 4927, EndLine: 4933}}},
		{ID: "cross-spawn@5.1.0", Name: "cross-spawn", Version: "5.1.0", Locations: []types.Location{{StartLine: 4935, EndLine: 4942}}},
		{ID: "crypt@0.0.2", Name: "crypt", Version: "0.0.2", Locations: []types.Location{{StartLine: 4944, EndLine: 4947}}},
		{ID: "crypto-browserify@3.12.0", Name: "crypto-browserify", Version: "3.12.0", Locations: []types.Location{{StartLine: 4949, EndLine: 4964}}},
		{ID: "crypto-random-string@1.0.0", Name: "crypto-random-string", Version: "1.0.0", Locations: []types.Location{{StartLine: 4966, EndLine: 4969}}},
		{ID: "css-color-keywords@1.0.0", Name: "css-color-keywords", Version: "1.0.0", Locations: []types.Location{{StartLine: 4971, EndLine: 4974}}},
		{ID: "css-loader@1.0.1", Name: "css-loader", Version: "1.0.1", Locations: []types.Location{{StartLine: 4976, EndLine: 4992}}},
		{ID: "css-select-base-adapter@0.1.1", Name: "css-select-base-adapter", Version: "0.1.1", Locations: []types.Location{{StartLine: 4994, EndLine: 4997}}},
		{ID: "css-select@1.2.0", Name: "css-select", Version: "1.2.0", Locations: []types.Location{{StartLine: 4999, EndLine: 5007}}},
		{ID: "css-select@2.0.2", Name: "css-select", Version: "2.0.2", Locations: []types.Location{{StartLine: 5009, EndLine: 5017}}},
		{ID: "css-selector-tokenizer@0.7.1", Name: "css-selector-tokenizer", Version: "0.7.1", Locations: []types.Location{{StartLine: 5019, EndLine: 5026}}},
		{ID: "css-to-react-native@2.3.1", Name: "css-to-react-native", Version: "2.3.1", Locations: []types.Location{{StartLine: 5028, EndLine: 5035}}},
		{ID: "css-tree@1.0.0-alpha.28", Name: "css-tree", Version: "1.0.0-alpha.28", Locations: []types.Location{{StartLine: 5037, EndLine: 5043}}},
		{ID: "css-tree@1.0.0-alpha.29", Name: "css-tree", Version: "1.0.0-alpha.29", Locations: []types.Location{{StartLine: 5045, EndLine: 5051}}},
		{ID: "css-url-regex@1.1.0", Name: "css-url-regex", Version: "1.1.0", Locations: []types.Location{{StartLine: 5053, EndLine: 5056}}},
		{ID: "css-vendor@0.3.8", Name: "css-vendor", Version: "0.3.8", Locations: []types.Location{{StartLine: 5058, EndLine: 5063}}},
		{ID: "css-what@2.1.3", Name: "css-what", Version: "2.1.3", Locations: []types.Location{{StartLine: 5065, EndLine: 5068}}},
		{ID: "cssesc@0.1.0", Name: "cssesc", Version: "0.1.0", Locations: []types.Location{{StartLine: 5070, EndLine: 5073}}},
		{ID: "csso@3.5.1", Name: "csso", Version: "3.5.1", Locations: []types.Location{{StartLine: 5075, EndLine: 5080}}},
		{ID: "cssom@0.3.6", Name: "cssom", Version: "0.3.6", Locations: []types.Location{{StartLine: 5082, EndLine: 5085}}},
		{ID: "cssstyle@1.2.2", Name: "cssstyle", Version: "1.2.2", Locations: []types.Location{{StartLine: 5087, EndLine: 5092}}},
		{ID: "csstype@2.6.4", Name: "csstype", Version: "2.6.4", Locations: []types.Location{{StartLine: 5094, EndLine: 5097}}},
		{ID: "cyclist@0.2.2", Name: "cyclist", Version: "0.2.2", Locations: []types.Location{{StartLine: 5099, EndLine: 5102}}},
		{ID: "damerau-levenshtein@1.0.5", Name: "damerau-levenshtein", Version: "1.0.5", Locations: []types.Location{{StartLine: 5104, EndLine: 5107}}},
		{ID: "dashdash@1.14.1", Name: "dashdash", Version: "1.14.1", Locations: []types.Location{{StartLine: 5109, EndLine: 5114}}},
		{ID: "data-urls@1.1.0", Name: "data-urls", Version: "1.1.0", Locations: []types.Location{{StartLine: 5116, EndLine: 5123}}},
		{ID: "date-fns@1.30.1", Name: "date-fns", Version: "1.30.1", Locations: []types.Location{{StartLine: 5125, EndLine: 5128}}},
		{ID: "date-fns@2.0.0-alpha.27", Name: "date-fns", Version: "2.0.0-alpha.27", Locations: []types.Location{{StartLine: 5130, EndLine: 5133}}},
		{ID: "date-now@0.1.4", Name: "date-now", Version: "0.1.4", Locations: []types.Location{{StartLine: 5135, EndLine: 5138}}},
		{ID: "debounce@1.2.0", Name: "debounce", Version: "1.2.0", Locations: []types.Location{{StartLine: 5140, EndLine: 5143}}},
		{ID: "debug@2.6.9", Name: "debug", Version: "2.6.9", Locations: []types.Location{{StartLine: 5145, EndLine: 5150}}},
		{ID: "debug@3.1.0", Name: "debug", Version: "3.1.0", Locations: []types.Location{{StartLine: 5152, EndLine: 5157}}},
		{ID: "debug@3.2.6", Name: "debug", Version: "3.2.6", Locations: []types.Location{{StartLine: 5159, EndLine: 5164}}},
		{ID: "debug@4.1.1", Name: "debug", Version: "4.1.1", Locations: []types.Location{{StartLine: 5166, EndLine: 5171}}},
		{ID: "debuglog@1.0.1", Name: "debuglog", Version: "1.0.1", Locations: []types.Location{{StartLine: 5173, EndLine: 5176}}},
		{ID: "decamelize@1.2.0", Name: "decamelize", Version: "1.2.0", Locations: []types.Location{{StartLine: 5178, EndLine: 5181}}},
		{ID: "decode-uri-component@0.2.0", Name: "decode-uri-component", Version: "0.2.0", Locations: []types.Location{{StartLine: 5183, EndLine: 5186}}},
		{ID: "decompress-response@3.3.0", Name: "decompress-response", Version: "3.3.0", Locations: []types.Location{{StartLine: 5188, EndLine: 5193}}},
		{ID: "dedent@0.7.0", Name: "dedent", Version: "0.7.0", Locations: []types.Location{{StartLine: 5195, EndLine: 5198}}},
		{ID: "deep-equal@1.0.1", Name: "deep-equal", Version: "1.0.1", Locations: []types.Location{{StartLine: 5200, EndLine: 5203}}},
		{ID: "deep-extend@0.6.0", Name: "deep-extend", Version: "0.6.0", Locations: []types.Location{{StartLine: 5205, EndLine: 5208}}},
		{ID: "deep-is@0.1.3", Name: "deep-is", Version: "0.1.3", Locations: []types.Location{{StartLine: 5210, EndLine: 5213}}},
		{ID: "deepmerge@2.2.1", Name: "deepmerge", Version: "2.2.1", Locations: []types.Location{{StartLine: 5215, EndLine: 5218}}},
		{ID: "deepmerge@3.2.0", Name: "deepmerge", Version: "3.2.0", Locations: []types.Location{{StartLine: 5220, EndLine: 5223}}},
		{ID: "default-gateway@4.2.0", Name: "default-gateway", Version: "4.2.0", Locations: []types.Location{{StartLine: 5225, EndLine: 5231}}},
		{ID: "default-require-extensions@1.0.0", Name: "default-require-extensions", Version: "1.0.0", Locations: []types.Location{{StartLine: 5233, EndLine: 5238}}},
		{ID: "defaults@1.0.3", Name: "defaults", Version: "1.0.3", Locations: []types.Location{{StartLine: 5240, EndLine: 5245}}},
		{ID: "define-properties@1.1.3", Name: "define-properties", Version: "1.1.3", Locations: []types.Location{{StartLine: 5247, EndLine: 5252}}},
		{ID: "define-property@0.2.5", Name: "define-property", Version: "0.2.5", Locations: []types.Location{{StartLine: 5254, EndLine: 5259}}},
		{ID: "define-property@1.0.0", Name: "define-property", Version: "1.0.0", Locations: []types.Location{{StartLine: 5261, EndLine: 5266}}},
		{ID: "define-property@2.0.2", Name: "define-property", Version: "2.0.2", Locations: []types.Location{{StartLine: 5268, EndLine: 5274}}},
		{ID: "del@3.0.0", Name: "del", Version: "3.0.0", Locations: []types.Location{{StartLine: 5276, EndLine: 5286}}},
		{ID: "del@4.1.1", Name: "del", Version: "4.1.1", Locations: []types.Location{{StartLine: 5288, EndLine: 5299}}},
		{ID: "delayed-stream@1.0.0", Name: "delayed-stream", Version: "1.0.0", Locations: []types.Location{{StartLine: 5301, EndLine: 5304}}},
		{ID: "delegates@1.0.0", Name: "delegates", Version: "1.0.0", Locations: []types.Location{{StartLine: 5306, EndLine: 5309}}},
		{ID: "depd@1.1.2", Name: "depd", Version: "1.1.2", Locations: []types.Location{{StartLine: 5311, EndLine: 5314}}},
		{ID: "des.js@1.0.0", Name: "des.js", Version: "1.0.0", Locations: []types.Location{{StartLine: 5316, EndLine: 5322}}},
		{ID: "destroy@1.0.4", Name: "destroy", Version: "1.0.4", Locations: []types.Location{{StartLine: 5324, EndLine: 5327}}},
		{ID: "detect-file@1.0.0", Name: "detect-file", Version: "1.0.0", Locations: []types.Location{{StartLine: 5329, EndLine: 5332}}},
		{ID: "detect-indent@4.0.0", Name: "detect-indent", Version: "4.0.0", Locations: []types.Location{{StartLine: 5334, EndLine: 5339}}},
		{ID: "detect-indent@5.0.0", Name: "detect-indent", Version: "5.0.0", Locations: []types.Location{{StartLine: 5341, EndLine: 5344}}},
		{ID: "detect-libc@1.0.3", Name: "detect-libc", Version: "1.0.3", Locations: []types.Location{{StartLine: 5346, EndLine: 5349}}},
		{ID: "detect-newline@2.1.0", Name: "detect-newline", Version: "2.1.0", Locations: []types.Location{{StartLine: 5351, EndLine: 5354}}},
		{ID: "detect-node@2.0.4", Name: "detect-node", Version: "2.0.4", Locations: []types.Location{{StartLine: 5356, EndLine: 5359}}},
		{ID: "detect-port-alt@1.1.6", Name: "detect-port-alt", Version: "1.1.6", Locations: []types.Location{{StartLine: 5361, EndLine: 5367}}},
		{ID: "detect-port@1.3.0", Name: "detect-port", Version: "1.3.0", Locations: []types.Location{{StartLine: 5369, EndLine: 5375}}},
		{ID: "dezalgo@1.0.3", Name: "dezalgo", Version: "1.0.3", Locations: []types.Location{{StartLine: 5377, EndLine: 5383}}},
		{ID: "diff@3.5.0", Name: "diff", Version: "3.5.0", Locations: []types.Location{{StartLine: 5385, EndLine: 5388}}},
		{ID: "diffie-hellman@5.0.3", Name: "diffie-hellman", Version: "5.0.3", Locations: []types.Location{{StartLine: 5390, EndLine: 5397}}},
		{ID: "dir-glob@2.2.2", Name: "dir-glob", Version: "2.2.2", Locations: []types.Location{{StartLine: 5399, EndLine: 5404}}},
		{ID: "discontinuous-range@1.0.0", Name: "discontinuous-range", Version: "1.0.0", Locations: []types.Location{{StartLine: 5406, EndLine: 5409}}},
		{ID: "dns-equal@1.0.0", Name: "dns-equal", Version: "1.0.0", Locations: []types.Location{{StartLine: 5411, EndLine: 5414}}},
		{ID: "dns-packet@1.3.1", Name: "dns-packet", Version: "1.3.1", Locations: []types.Location{{StartLine: 5416, EndLine: 5422}}},
		{ID: "dns-txt@2.0.2", Name: "dns-txt", Version: "2.0.2", Locations: []types.Location{{StartLine: 5424, EndLine: 5429}}},
		{ID: "doctrine@1.5.0", Name: "doctrine", Version: "1.5.0", Locations: []types.Location{{StartLine: 5431, EndLine: 5437}}},
		{ID: "doctrine@2.1.0", Name: "doctrine", Version: "2.1.0", Locations: []types.Location{{StartLine: 5439, EndLine: 5444}}},
		{ID: "doctrine@3.0.0", Name: "doctrine", Version: "3.0.0", Locations: []types.Location{{StartLine: 5446, EndLine: 5451}}},
		{ID: "dom-converter@0.2.0", Name: "dom-converter", Version: "0.2.0", Locations: []types.Location{{StartLine: 5453, EndLine: 5458}}},
		{ID: "dom-helpers@3.4.0", Name: "dom-helpers", Version: "3.4.0", Locations: []types.Location{{StartLine: 5460, EndLine: 5465}}},
		{ID: "dom-serializer@0.1.1", Name: "dom-serializer", Version: "0.1.1", Locations: []types.Location{{StartLine: 5467, EndLine: 5473}}},
		{ID: "dom-walk@0.1.1", Name: "dom-walk", Version: "0.1.1", Locations: []types.Location{{StartLine: 5475, EndLine: 5478}}},
		{ID: "domain-browser@1.2.0", Name: "domain-browser", Version: "1.2.0", Locations: []types.Location{{StartLine: 5480, EndLine: 5483}}},
		{ID: "domelementtype@1.3.1", Name: "domelementtype", Version: "1.3.1", Locations: []types.Location{{StartLine: 5485, EndLine: 5488}}},
		{ID: "domexception@1.0.1", Name: "domexception", Version: "1.0.1", Locations: []types.Location{{StartLine: 5490, EndLine: 5495}}},
		{ID: "domhandler@2.4.2", Name: "domhandler", Version: "2.4.2", Locations: []types.Location{{StartLine: 5497, EndLine: 5502}}},
		{ID: "domutils@1.5.1", Name: "domutils", Version: "1.5.1", Locations: []types.Location{{StartLine: 5504, EndLine: 5510}}},
		{ID: "domutils@1.7.0", Name: "domutils", Version: "1.7.0", Locations: []types.Location{{StartLine: 5512, EndLine: 5518}}},
		{ID: "dot-prop@4.2.0", Name: "dot-prop", Version: "4.2.0", Locations: []types.Location{{StartLine: 5520, EndLine: 5525}}},
		{ID: "dotenv-defaults@1.0.2", Name: "dotenv-defaults", Version: "1.0.2", Locations: []types.Location{{StartLine: 5527, EndLine: 5532}}},
		{ID: "dotenv-expand@4.2.0", Name: "dotenv-expand", Version: "4.2.0", Locations: []types.Location{{StartLine: 5534, EndLine: 5537}}},
		{ID: "dotenv-webpack@1.7.0", Name: "dotenv-webpack", Version: "1.7.0", Locations: []types.Location{{StartLine: 5539, EndLine: 5544}}},
		{ID: "dotenv@5.0.1", Name: "dotenv", Version: "5.0.1", Locations: []types.Location{{StartLine: 5546, EndLine: 5549}}},
		{ID: "dotenv@6.2.0", Name: "dotenv", Version: "6.2.0", Locations: []types.Location{{StartLine: 5551, EndLine: 5554}}},
		{ID: "duplexer2@0.1.4", Name: "duplexer2", Version: "0.1.4", Locations: []types.Location{{StartLine: 5556, EndLine: 5561}}},
		{ID: "duplexer3@0.1.4", Name: "duplexer3", Version: "0.1.4", Locations: []types.Location{{StartLine: 5563, EndLine: 5566}}},
		{ID: "duplexer@0.1.1", Name: "duplexer", Version: "0.1.1", Locations: []types.Location{{StartLine: 5568, EndLine: 5571}}},
		{ID: "duplexify@3.7.1", Name: "duplexify", Version: "3.7.1", Locations: []types.Location{{StartLine: 5573, EndLine: 5581}}},
		{ID: "ecc-jsbn@0.1.2", Name: "ecc-jsbn", Version: "0.1.2", Locations: []types.Location{{StartLine: 5583, EndLine: 5589}}},
		{ID: "editor@1.0.0", Name: "editor", Version: "1.0.0", Locations: []types.Location{{StartLine: 5591, EndLine: 5594}}},
		{ID: "ee-first@1.1.1", Name: "ee-first", Version: "1.1.1", Locations: []types.Location{{StartLine: 5596, EndLine: 5599}}},
		{ID: "ejs@2.6.1", Name: "ejs", Version: "2.6.1", Locations: []types.Location{{StartLine: 5601, EndLine: 5604}}},
		{ID: "electron-to-chromium@1.3.134", Name: "electron-to-chromium", Version: "1.3.134", Locations: []types.Location{{StartLine: 5606, EndLine: 5609}}},
		{ID: "elegant-spinner@1.0.1", Name: "elegant-spinner", Version: "1.0.1", Locations: []types.Location{{StartLine: 5611, EndLine: 5614}}},
		{ID: "elliptic@6.4.1", Name: "elliptic", Version: "6.4.1", Locations: []types.Location{{StartLine: 5616, EndLine: 5627}}},
		{ID: "emoji-regex@7.0.3", Name: "emoji-regex", Version: "7.0.3", Locations: []types.Location{{StartLine: 5629, EndLine: 5632}}},
		{ID: "emojis-list@2.1.0", Name: "emojis-list", Version: "2.1.0", Locations: []types.Location{{StartLine: 5634, EndLine: 5637}}},
		{ID: "encodeurl@1.0.2", Name: "encodeurl", Version: "1.0.2", Locations: []types.Location{{StartLine: 5639, EndLine: 5642}}},
		{ID: "encoding@0.1.12", Name: "encoding", Version: "0.1.12", Locations: []types.Location{{StartLine: 5644, EndLine: 5649}}},
		{ID: "end-of-stream@1.4.1", Name: "end-of-stream", Version: "1.4.1", Locations: []types.Location{{StartLine: 5651, EndLine: 5656}}},
		{ID: "engine.io-client@3.3.2", Name: "engine.io-client", Version: "3.3.2", Locations: []types.Location{{StartLine: 5658, EndLine: 5673}}},
		{ID: "engine.io-parser@2.1.3", Name: "engine.io-parser", Version: "2.1.3", Locations: []types.Location{{StartLine: 5675, EndLine: 5684}}},
		{ID: "engine.io@3.3.2", Name: "engine.io", Version: "3.3.2", Locations: []types.Location{{StartLine: 5686, EndLine: 5696}}},
		{ID: "enhanced-resolve@4.1.0", Name: "enhanced-resolve", Version: "4.1.0", Locations: []types.Location{{StartLine: 5698, EndLine: 5705}}},
		{ID: "entities@1.1.2", Name: "entities", Version: "1.1.2", Locations: []types.Location{{StartLine: 5707, EndLine: 5710}}},
		{ID: "enzyme-adapter-react-16@1.13.0", Name: "enzyme-adapter-react-16", Version: "1.13.0", Locations: []types.Location{{StartLine: 5712, EndLine: 5723}}},
		{ID: "enzyme-adapter-utils@1.12.0", Name: "enzyme-adapter-utils", Version: "1.12.0", Locations: []types.Location{{StartLine: 5725, EndLine: 5735}}},
		{ID: "enzyme@3.9.0", Name: "enzyme", Version: "3.9.0", Locations: []types.Location{{StartLine: 5737, EndLine: 5762}}},
		{ID: "err-code@1.1.2", Name: "err-code", Version: "1.1.2", Locations: []types.Location{{StartLine: 5764, EndLine: 5767}}},
		{ID: "errno@0.1.7", Name: "errno", Version: "0.1.7", Locations: []types.Location{{StartLine: 5769, EndLine: 5774}}},
		{ID: "error-ex@1.3.2", Name: "error-ex", Version: "1.3.2", Locations: []types.Location{{StartLine: 5776, EndLine: 5781}}},
		{ID: "es-abstract@1.13.0", Name: "es-abstract", Version: "1.13.0", Locations: []types.Location{{StartLine: 5783, EndLine: 5793}}},
		{ID: "es-to-primitive@1.2.0", Name: "es-to-primitive", Version: "1.2.0", Locations: []types.Location{{StartLine: 5795, EndLine: 5802}}},
		{ID: "es5-shim@4.5.13", Name: "es5-shim", Version: "4.5.13", Locations: []types.Location{{StartLine: 5804, EndLine: 5807}}},
		{ID: "es6-promise-promise@1.0.0", Name: "es6-promise-promise", Version: "1.0.0", Locations: []types.Location{{StartLine: 5809, EndLine: 5814}}},
		{ID: "es6-promise@3.3.1", Name: "es6-promise", Version: "3.3.1", Locations: []types.Location{{StartLine: 5816, EndLine: 5819}}},
		{ID: "es6-promise@4.2.6", Name: "es6-promise", Version: "4.2.6", Locations: []types.Location{{StartLine: 5821, EndLine: 5824}}},
		{ID: "es6-promisify@5.0.0", Name: "es6-promisify", Version: "5.0.0", Locations: []types.Location{{StartLine: 5826, EndLine: 5831}}},
		{ID: "es6-shim@0.35.5", Name: "es6-shim", Version: "0.35.5", Locations: []types.Location{{StartLine: 5833, EndLine: 5836}}},
		{ID: "escape-html@1.0.3", Name: "escape-html", Version: "1.0.3", Locations: []types.Location{{StartLine: 5838, EndLine: 5841}}},
		{ID: "escape-string-regexp@1.0.5", Name: "escape-string-regexp", Version: "1.0.5", Locations: []types.Location{{StartLine: 5843, EndLine: 5846}}},
		{ID: "escodegen@1.11.1", Name: "escodegen", Version: "1.11.1", Locations: []types.Location{{StartLine: 5848, EndLine: 5858}}},
		{ID: "eslint-config-airbnb-base@13.1.0", Name: "eslint-config-airbnb-base", Version: "13.1.0", Locations: []types.Location{{StartLine: 5860, EndLine: 5867}}},
		{ID: "eslint-config-airbnb@17.1.0", Name: "eslint-config-airbnb", Version: "17.1.0", Locations: []types.Location{{StartLine: 5869, EndLine: 5876}}},
		{ID: "eslint-import-resolver-node@0.3.2", Name: "eslint-import-resolver-node", Version: "0.3.2", Locations: []types.Location{{StartLine: 5878, EndLine: 5884}}},
		{ID: "eslint-loader@2.1.2", Name: "eslint-loader", Version: "2.1.2", Locations: []types.Location{{StartLine: 5886, EndLine: 5895}}},
		{ID: "eslint-module-utils@2.4.0", Name: "eslint-module-utils", Version: "2.4.0", Locations: []types.Location{{StartLine: 5897, EndLine: 5903}}},
		{ID: "eslint-plugin-import@2.17.2", Name: "eslint-plugin-import", Version: "2.17.2", Locations: []types.Location{{StartLine: 5905, EndLine: 5920}}},
		{ID: "eslint-plugin-jsx-a11y@6.2.1", Name: "eslint-plugin-jsx-a11y", Version: "6.2.1", Locations: []types.Location{{StartLine: 5922, EndLine: 5934}}},
		{ID: "eslint-plugin-react@7.13.0", Name: "eslint-plugin-react", Version: "7.13.0", Locations: []types.Location{{StartLine: 5936, EndLine: 5947}}},
		{ID: "eslint-restricted-globals@0.1.1", Name: "eslint-restricted-globals", Version: "0.1.1", Locations: []types.Location{{StartLine: 5949, EndLine: 5952}}},
		{ID: "eslint-scope@3.7.1", Name: "eslint-scope", Version: "3.7.1", Locations: []types.Location{{StartLine: 5954, EndLine: 5960}}},
		{ID: "eslint-scope@4.0.3", Name: "eslint-scope", Version: "4.0.3", Locations: []types.Location{{StartLine: 5962, EndLine: 5968}}},
		{ID: "eslint-utils@1.3.1", Name: "eslint-utils", Version: "1.3.1", Locations: []types.Location{{StartLine: 5970, EndLine: 5973}}},
		{ID: "eslint-visitor-keys@1.0.0", Name: "eslint-visitor-keys", Version: "1.0.0", Locations: []types.Location{{StartLine: 5975, EndLine: 5978}}},
		{ID: "eslint@5.16.0", Name: "eslint", Version: "5.16.0", Locations: []types.Location{{StartLine: 5980, EndLine: 6020}}},
		{ID: "espree@5.0.1", Name: "espree", Version: "5.0.1", Locations: []types.Location{{StartLine: 6022, EndLine: 6029}}},
		{ID: "esprima@3.1.3", Name: "esprima", Version: "3.1.3", Locations: []types.Location{{StartLine: 6031, EndLine: 6034}}},
		{ID: "esprima@4.0.1", Name: "esprima", Version: "4.0.1", Locations: []types.Location{{StartLine: 6036, EndLine: 6039}}},
		{ID: "esquery@1.0.1", Name: "esquery", Version: "1.0.1", Locations: []types.Location{{StartLine: 6041, EndLine: 6046}}},
		{ID: "esrecurse@4.2.1", Name: "esrecurse", Version: "4.2.1", Locations: []types.Location{{StartLine: 6048, EndLine: 6053}}},
		{ID: "estraverse@4.2.0", Name: "estraverse", Version: "4.2.0", Locations: []types.Location{{StartLine: 6055, EndLine: 6058}}},
		{ID: "esutils@2.0.2", Name: "esutils", Version: "2.0.2", Locations: []types.Location{{StartLine: 6060, EndLine: 6063}}},
		{ID: "etag@1.8.1", Name: "etag", Version: "1.8.1", Locations: []types.Location{{StartLine: 6065, EndLine: 6068}}},
		{ID: "eventemitter3@3.1.2", Name: "eventemitter3", Version: "3.1.2", Locations: []types.Location{{StartLine: 6070, EndLine: 6073}}},
		{ID: "events@3.0.0", Name: "events", Version: "3.0.0", Locations: []types.Location{{StartLine: 6075, EndLine: 6078}}},
		{ID: "eventsource@0.1.6", Name: "eventsource", Version: "0.1.6", Locations: []types.Location{{StartLine: 6080, EndLine: 6085}}},
		{ID: "eventsource@1.0.7", Name: "eventsource", Version: "1.0.7", Locations: []types.Location{{StartLine: 6087, EndLine: 6092}}},
		{ID: "evp_bytestokey@1.0.3", Name: "evp_bytestokey", Version: "1.0.3", Locations: []types.Location{{StartLine: 6094, EndLine: 6100}}},
		{ID: "exec-sh@0.2.2", Name: "exec-sh", Version: "0.2.2", Locations: []types.Location{{StartLine: 6102, EndLine: 6107}}},
		{ID: "execa@0.7.0", Name: "execa", Version: "0.7.0", Locations: []types.Location{{StartLine: 6109, EndLine: 6120}}},
		{ID: "execa@0.9.0", Name: "execa", Version: "0.9.0", Locations: []types.Location{{StartLine: 6122, EndLine: 6133}}},
		{ID: "execa@1.0.0", Name: "execa", Version: "1.0.0", Locations: []types.Location{{StartLine: 6135, EndLine: 6146}}},
		{ID: "exenv@1.2.2", Name: "exenv", Version: "1.2.2", Locations: []types.Location{{StartLine: 6148, EndLine: 6151}}},
		{ID: "exit-hook@1.1.1", Name: "exit-hook", Version: "1.1.1", Locations: []types.Location{{StartLine: 6153, EndLine: 6156}}},
		{ID: "exit@0.1.2", Name: "exit", Version: "0.1.2", Locations: []types.Location{{StartLine: 6158, EndLine: 6161}}},
		{ID: "expand-brackets@0.1.5", Name: "expand-brackets", Version: "0.1.5", Locations: []types.Location{{StartLine: 6163, EndLine: 6168}}},
		{ID: "expand-brackets@2.1.4", Name: "expand-brackets", Version: "2.1.4", Locations: []types.Location{{StartLine: 6170, EndLine: 6181}}},
		{ID: "expand-range@1.8.2", Name: "expand-range", Version: "1.8.2", Locations: []types.Location{{StartLine: 6183, EndLine: 6188}}},
		{ID: "expand-tilde@2.0.2", Name: "expand-tilde", Version: "2.0.2", Locations: []types.Location{{StartLine: 6190, EndLine: 6195}}},
		{ID: "expect@23.6.0", Name: "expect", Version: "23.6.0", Locations: []types.Location{{StartLine: 6197, EndLine: 6207}}},
		{ID: "express@4.16.4", Name: "express", Version: "4.16.4", Locations: []types.Location{{StartLine: 6209, EndLine: 6243}}},
		{ID: "extend-shallow@2.0.1", Name: "extend-shallow", Version: "2.0.1", Locations: []types.Location{{StartLine: 6245, EndLine: 6250}}},
		{ID: "extend-shallow@3.0.2", Name: "extend-shallow", Version: "3.0.2", Locations: []types.Location{{StartLine: 6252, EndLine: 6258}}},
		{ID: "extend@3.0.2", Name: "extend", Version: "3.0.2", Locations: []types.Location{{StartLine: 6260, EndLine: 6263}}},
		{ID: "external-editor@3.0.3", Name: "external-editor", Version: "3.0.3", Locations: []types.Location{{StartLine: 6265, EndLine: 6272}}},
		{ID: "extglob@0.3.2", Name: "extglob", Version: "0.3.2", Locations: []types.Location{{StartLine: 6274, EndLine: 6279}}},
		{ID: "extglob@2.0.4", Name: "extglob", Version: "2.0.4", Locations: []types.Location{{StartLine: 6281, EndLine: 6293}}},
		{ID: "extract-text-webpack-plugin@4.0.0-beta.0", Name: "extract-text-webpack-plugin", Version: "4.0.0-beta.0", Locations: []types.Location{{StartLine: 6295, EndLine: 6303}}},
		{ID: "extsprintf@1.3.0", Name: "extsprintf", Version: "1.3.0", Locations: []types.Location{{StartLine: 6305, EndLine: 6308}}},
		{ID: "extsprintf@1.4.0", Name: "extsprintf", Version: "1.4.0", Locations: []types.Location{{StartLine: 6310, EndLine: 6313}}},
		{ID: "faker@4.1.0", Name: "faker", Version: "4.1.0", Locations: []types.Location{{StartLine: 6315, EndLine: 6318}}},
		{ID: "fast-deep-equal@2.0.1", Name: "fast-deep-equal", Version: "2.0.1", Locations: []types.Location{{StartLine: 6320, EndLine: 6323}}},
		{ID: "fast-glob@2.2.6", Name: "fast-glob", Version: "2.2.6", Locations: []types.Location{{StartLine: 6325, EndLine: 6335}}},
		{ID: "fast-json-stable-stringify@2.0.0", Name: "fast-json-stable-stringify", Version: "2.0.0", Locations: []types.Location{{StartLine: 6337, EndLine: 6340}}},
		{ID: "fast-levenshtein@2.0.6", Name: "fast-levenshtein", Version: "2.0.6", Locations: []types.Location{{StartLine: 6342, EndLine: 6345}}},
		{ID: "fastparse@1.1.2", Name: "fastparse", Version: "1.1.2", Locations: []types.Location{{StartLine: 6347, EndLine: 6350}}},
		{ID: "faye-websocket@0.10.0", Name: "faye-websocket", Version: "0.10.0", Locations: []types.Location{{StartLine: 6352, EndLine: 6357}}},
		{ID: "faye-websocket@0.11.1", Name: "faye-websocket", Version: "0.11.1", Locations: []types.Location{{StartLine: 6359, EndLine: 6364}}},
		{ID: "fb-watchman@2.0.0", Name: "fb-watchman", Version: "2.0.0", Locations: []types.Location{{StartLine: 6366, EndLine: 6371}}},
		{ID: "fbjs@0.8.17", Name: "fbjs", Version: "0.8.17", Locations: []types.Location{{StartLine: 6373, EndLine: 6384}}},
		{ID: "figgy-pudding@3.5.1", Name: "figgy-pudding", Version: "3.5.1", Locations: []types.Location{{StartLine: 6386, EndLine: 6389}}},
		{ID: "figures@1.7.0", Name: "figures", Version: "1.7.0", Locations: []types.Location{{StartLine: 6391, EndLine: 6397}}},
		{ID: "figures@2.0.0", Name: "figures", Version: "2.0.0", Locations: []types.Location{{StartLine: 6399, EndLine: 6404}}},
		{ID: "file-entry-cache@5.0.1", Name: "file-entry-cache", Version: "5.0.1", Locations: []types.Location{{StartLine: 6406, EndLine: 6411}}},
		{ID: "file-loader@1.1.11", Name: "file-loader", Version: "1.1.11", Locations: []types.Location{{StartLine: 6413, EndLine: 6419}}},
		{ID: "file-loader@2.0.0", Name: "file-loader", Version: "2.0.0", Locations: []types.Location{{StartLine: 6421, EndLine: 6427}}},
		{ID: "file-selector@0.1.11", Name: "file-selector", Version: "0.1.11", Locations: []types.Location{{StartLine: 6429, EndLine: 6434}}},
		{ID: "file-system-cache@1.0.5", Name: "file-system-cache", Version: "1.0.5", Locations: []types.Location{{StartLine: 6436, EndLine: 6443}}},
		{ID: "filename-regex@2.0.1", Name: "filename-regex", Version: "2.0.1", Locations: []types.Location{{StartLine: 6445, EndLine: 6448}}},
		{ID: "fileset@2.0.3", Name: "fileset", Version: "2.0.3", Locations: []types.Location{{StartLine: 6450, EndLine: 6456}}},
		{ID: "filesize@3.6.1", Name: "filesize", Version: "3.6.1", Locations: []types.Location{{StartLine: 6458, EndLine: 6461}}},
		{ID: "fill-range@2.2.4", Name: "fill-range", Version: "2.2.4", Locations: []types.Location{{StartLine: 6463, EndLine: 6472}}},
		{ID: "fill-range@4.0.0", Name: "fill-range", Version: "4.0.0", Locations: []types.Location{{StartLine: 6474, EndLine: 6482}}},
		{ID: "finalhandler@1.1.1", Name: "finalhandler", Version: "1.1.1", Locations: []types.Location{{StartLine: 6484, EndLine: 6495}}},
		{ID: "find-cache-dir@0.1.1", Name: "find-cache-dir", Version: "0.1.1", Locations: []types.Location{{StartLine: 6497, EndLine: 6504}}},
		{ID: "find-cache-dir@1.0.0", Name: "find-cache-dir", Version: "1.0.0", Locations: []types.Location{{StartLine: 6506, EndLine: 6513}}},
		{ID: "find-cache-dir@2.1.0", Name: "find-cache-dir", Version: "2.1.0", Locations: []types.Location{{StartLine: 6515, EndLine: 6522}}},
		{ID: "find-npm-prefix@1.0.2", Name: "find-npm-prefix", Version: "1.0.2", Locations: []types.Location{{StartLine: 6524, EndLine: 6527}}},
		{ID: "find-parent-dir@0.3.0", Name: "find-parent-dir", Version: "0.3.0", Locations: []types.Location{{StartLine: 6529, EndLine: 6532}}},
		{ID: "find-up@3.0.0", Name: "find-up", Version: "3.0.0", Locations: []types.Location{{StartLine: 6534, EndLine: 6539}}},
		{ID: "find-up@1.1.2", Name: "find-up", Version: "1.1.2", Locations: []types.Location{{StartLine: 6541, EndLine: 6547}}},
		{ID: "find-up@2.1.0", Name: "find-up", Version: "2.1.0", Locations: []types.Location{{StartLine: 6549, EndLine: 6554}}},
		{ID: "findup-sync@2.0.0", Name: "findup-sync", Version: "2.0.0", Locations: []types.Location{{StartLine: 6556, EndLine: 6564}}},
		{ID: "flat-cache@2.0.1", Name: "flat-cache", Version: "2.0.1", Locations: []types.Location{{StartLine: 6566, EndLine: 6573}}},
		{ID: "flatted@2.0.0", Name: "flatted", Version: "2.0.0", Locations: []types.Location{{StartLine: 6575, EndLine: 6578}}},
		{ID: "flow-bin@0.89.0", Name: "flow-bin", Version: "0.89.0", Locations: []types.Location{{StartLine: 6580, EndLine: 6583}}},
		{ID: "flow-parser@0.98.1", Name: "flow-parser", Version: "0.98.1", Locations: []types.Location{{StartLine: 6585, EndLine: 6588}}},
		{ID: "flow-typed@2.5.1", Name: "flow-typed", Version: "2.5.1", Locations: []types.Location{{StartLine: 6590, EndLine: 6609}}},
		{ID: "flush-write-stream@1.1.1", Name: "flush-write-stream", Version: "1.1.1", Locations: []types.Location{{StartLine: 6611, EndLine: 6617}}},
		{ID: "follow-redirects@1.7.0", Name: "follow-redirects", Version: "1.7.0", Locations: []types.Location{{StartLine: 6619, EndLine: 6624}}},
		{ID: "for-in@0.1.8", Name: "for-in", Version: "0.1.8", Locations: []types.Location{{StartLine: 6626, EndLine: 6629}}},
		{ID: "for-in@1.0.2", Name: "for-in", Version: "1.0.2", Locations: []types.Location{{StartLine: 6631, EndLine: 6634}}},
		{ID: "for-own@0.1.5", Name: "for-own", Version: "0.1.5", Locations: []types.Location{{StartLine: 6636, EndLine: 6641}}},
		{ID: "forever-agent@0.6.1", Name: "forever-agent", Version: "0.6.1", Locations: []types.Location{{StartLine: 6643, EndLine: 6646}}},
		{ID: "form-data@2.3.3", Name: "form-data", Version: "2.3.3", Locations: []types.Location{{StartLine: 6648, EndLine: 6655}}},
		{ID: "formik@1.5.1", Name: "formik", Version: "1.5.1", Locations: []types.Location{{StartLine: 6657, EndLine: 6670}}},
		{ID: "forwarded@0.1.2", Name: "forwarded", Version: "0.1.2", Locations: []types.Location{{StartLine: 6672, EndLine: 6675}}},
		{ID: "fragment-cache@0.2.1", Name: "fragment-cache", Version: "0.2.1", Locations: []types.Location{{StartLine: 6677, EndLine: 6682}}},
		{ID: "fresh@0.5.2", Name: "fresh", Version: "0.5.2", Locations: []types.Location{{StartLine: 6684, EndLine: 6687}}},
		{ID: "from2@1.3.0", Name: "from2", Version: "1.3.0", Locations: []types.Location{{StartLine: 6689, EndLine: 6695}}},
		{ID: "from2@2.3.0", Name: "from2", Version: "2.3.0", Locations: []types.Location{{StartLine: 6697, EndLine: 6703}}},
		{ID: "fs-extra@0.30.0", Name: "fs-extra", Version: "0.30.0", Locations: []types.Location{{StartLine: 6705, EndLine: 6714}}},
		{ID: "fs-extra@5.0.0", Name: "fs-extra", Version: "5.0.0", Locations: []types.Location{{StartLine: 6716, EndLine: 6723}}},
		{ID: "fs-extra@7.0.1", Name: "fs-extra", Version: "7.0.1", Locations: []types.Location{{StartLine: 6725, EndLine: 6732}}},
		{ID: "fs-minipass@1.2.5", Name: "fs-minipass", Version: "1.2.5", Locations: []types.Location{{StartLine: 6734, EndLine: 6739}}},
		{ID: "fs-readdir-recursive@1.1.0", Name: "fs-readdir-recursive", Version: "1.1.0", Locations: []types.Location{{StartLine: 6741, EndLine: 6744}}},
		{ID: "fs-vacuum@1.2.10", Name: "fs-vacuum", Version: "1.2.10", Locations: []types.Location{{StartLine: 6746, EndLine: 6753}}},
		{ID: "fs-write-stream-atomic@1.0.10", Name: "fs-write-stream-atomic", Version: "1.0.10", Locations: []types.Location{{StartLine: 6755, EndLine: 6763}}},
		{ID: "fs.realpath@1.0.0", Name: "fs.realpath", Version: "1.0.0", Locations: []types.Location{{StartLine: 6765, EndLine: 6768}}},
		{ID: "fsevents@1.2.9", Name: "fsevents", Version: "1.2.9", Locations: []types.Location{{StartLine: 6770, EndLine: 6776}}},
		{ID: "fstream@1.0.12", Name: "fstream", Version: "1.0.12", Locations: []types.Location{{StartLine: 6778, EndLine: 6786}}},
		{ID: "function-bind@1.1.1", Name: "function-bind", Version: "1.1.1", Locations: []types.Location{{StartLine: 6788, EndLine: 6791}}},
		{ID: "function.prototype.name@1.1.0", Name: "function.prototype.name", Version: "1.1.0", Locations: []types.Location{{StartLine: 6793, EndLine: 6800}}},
		{ID: "functional-red-black-tree@1.0.1", Name: "functional-red-black-tree", Version: "1.0.1", Locations: []types.Location{{StartLine: 6802, EndLine: 6805}}},
		{ID: "fuse.js@3.4.4", Name: "fuse.js", Version: "3.4.4", Locations: []types.Location{{StartLine: 6807, EndLine: 6810}}},
		{ID: "gauge@2.7.4", Name: "gauge", Version: "2.7.4", Locations: []types.Location{{StartLine: 6812, EndLine: 6824}}},
		{ID: "genfun@5.0.0", Name: "genfun", Version: "5.0.0", Locations: []types.Location{{StartLine: 6826, EndLine: 6829}}},
		{ID: "gentle-fs@2.0.1", Name: "gentle-fs", Version: "2.0.1", Locations: []types.Location{{StartLine: 6831, EndLine: 6843}}},
		{ID: "get-caller-file@1.0.3", Name: "get-caller-file", Version: "1.0.3", Locations: []types.Location{{StartLine: 6845, EndLine: 6848}}},
		{ID: "get-own-enumerable-property-symbols@3.0.0", Name: "get-own-enumerable-property-symbols", Version: "3.0.0", Locations: []types.Location{{StartLine: 6850, EndLine: 6853}}},
		{ID: "get-stdin@6.0.0", Name: "get-stdin", Version: "6.0.0", Locations: []types.Location{{StartLine: 6855, EndLine: 6858}}},
		{ID: "get-stream@3.0.0", Name: "get-stream", Version: "3.0.0", Locations: []types.Location{{StartLine: 6860, EndLine: 6863}}},
		{ID: "get-stream@4.1.0", Name: "get-stream", Version: "4.1.0", Locations: []types.Location{{StartLine: 6865, EndLine: 6870}}},
		{ID: "get-value@2.0.6", Name: "get-value", Version: "2.0.6", Locations: []types.Location{{StartLine: 6872, EndLine: 6875}}},
		{ID: "getpass@0.1.7", Name: "getpass", Version: "0.1.7", Locations: []types.Location{{StartLine: 6877, EndLine: 6882}}},
		{ID: "glob-base@0.3.0", Name: "glob-base", Version: "0.3.0", Locations: []types.Location{{StartLine: 6884, EndLine: 6890}}},
		{ID: "glob-parent@2.0.0", Name: "glob-parent", Version: "2.0.0", Locations: []types.Location{{StartLine: 6892, EndLine: 6897}}},
		{ID: "glob-parent@3.1.0", Name: "glob-parent", Version: "3.1.0", Locations: []types.Location{{StartLine: 6899, EndLine: 6905}}},
		{ID: "glob-to-regexp@0.3.0", Name: "glob-to-regexp", Version: "0.3.0", Locations: []types.Location{{StartLine: 6907, EndLine: 6910}}},
		{ID: "glob@7.1.4", Name: "glob", Version: "7.1.4", Locations: []types.Location{{StartLine: 6912, EndLine: 6922}}},
		{ID: "global-dirs@0.1.1", Name: "global-dirs", Version: "0.1.1", Locations: []types.Location{{StartLine: 6924, EndLine: 6929}}},
		{ID: "global-modules@1.0.0", Name: "global-modules", Version: "1.0.0", Locations: []types.Location{{StartLine: 6931, EndLine: 6938}}},
		{ID: "global-prefix@1.0.2", Name: "global-prefix", Version: "1.0.2", Locations: []types.Location{{StartLine: 6940, EndLine: 6949}}},
		{ID: "global@4.3.2", Name: "global", Version: "4.3.2", Locations: []types.Location{{StartLine: 6951, EndLine: 6957}}},
		{ID: "globals@11.12.0", Name: "globals", Version: "11.12.0", Locations: []types.Location{{StartLine: 6959, EndLine: 6962}}},
		{ID: "globals@9.18.0", Name: "globals", Version: "9.18.0", Locations: []types.Location{{StartLine: 6964, EndLine: 6967}}},
		{ID: "globalthis@1.0.0", Name: "globalthis", Version: "1.0.0", Locations: []types.Location{{StartLine: 6969, EndLine: 6976}}},
		{ID: "globby@8.0.1", Name: "globby", Version: "8.0.1", Locations: []types.Location{{StartLine: 6978, EndLine: 6989}}},
		{ID: "globby@6.1.0", Name: "globby", Version: "6.1.0", Locations: []types.Location{{StartLine: 6991, EndLine: 7000}}},
		{ID: "globby@7.1.1", Name: "globby", Version: "7.1.1", Locations: []types.Location{{StartLine: 7002, EndLine: 7012}}},
		{ID: "got@6.7.1", Name: "got", Version: "6.7.1", Locations: []types.Location{{StartLine: 7014, EndLine: 7029}}},
		{ID: "got@7.1.0", Name: "got", Version: "7.1.0", Locations: []types.Location{{StartLine: 7031, EndLine: 7049}}},
		{ID: "graceful-fs@4.1.15", Name: "graceful-fs", Version: "4.1.15", Locations: []types.Location{{StartLine: 7051, EndLine: 7054}}},
		{ID: "growly@1.3.0", Name: "growly", Version: "1.3.0", Locations: []types.Location{{StartLine: 7056, EndLine: 7059}}},
		{ID: "gud@1.0.0", Name: "gud", Version: "1.0.0", Locations: []types.Location{{StartLine: 7061, EndLine: 7064}}},
		{ID: "gzip-size@5.0.0", Name: "gzip-size", Version: "5.0.0", Locations: []types.Location{{StartLine: 7066, EndLine: 7072}}},
		{ID: "gzip-size@5.1.0", Name: "gzip-size", Version: "5.1.0", Locations: []types.Location{{StartLine: 7074, EndLine: 7080}}},
		{ID: "handle-thing@2.0.0", Name: "handle-thing", Version: "2.0.0", Locations: []types.Location{{StartLine: 7082, EndLine: 7085}}},
		{ID: "handlebars@4.1.2", Name: "handlebars", Version: "4.1.2", Locations: []types.Location{{StartLine: 7087, EndLine: 7096}}},
		{ID: "har-schema@2.0.0", Name: "har-schema", Version: "2.0.0", Locations: []types.Location{{StartLine: 7098, EndLine: 7101}}},
		{ID: "har-validator@5.1.3", Name: "har-validator", Version: "5.1.3", Locations: []types.Location{{StartLine: 7103, EndLine: 7109}}},
		{ID: "hard-source-webpack-plugin@0.13.1", Name: "hard-source-webpack-plugin", Version: "0.13.1", Locations: []types.Location{{StartLine: 7111, EndLine: 7128}}},
		{ID: "has-ansi@2.0.0", Name: "has-ansi", Version: "2.0.0", Locations: []types.Location{{StartLine: 7130, EndLine: 7135}}},
		{ID: "has-binary2@1.0.3", Name: "has-binary2", Version: "1.0.3", Locations: []types.Location{{StartLine: 7137, EndLine: 7142}}},
		{ID: "has-color@0.1.7", Name: "has-color", Version: "0.1.7", Locations: []types.Location{{StartLine: 7144, EndLine: 7147}}},
		{ID: "has-cors@1.1.0", Name: "has-cors", Version: "1.1.0", Locations: []types.Location{{StartLine: 7149, EndLine: 7152}}},
		{ID: "has-flag@1.0.0", Name: "has-flag", Version: "1.0.0", Locations: []types.Location{{StartLine: 7154, EndLine: 7157}}},
		{ID: "has-flag@3.0.0", Name: "has-flag", Version: "3.0.0", Locations: []types.Location{{StartLine: 7159, EndLine: 7162}}},
		{ID: "has-symbol-support-x@1.4.2", Name: "has-symbol-support-x", Version: "1.4.2", Locations: []types.Location{{StartLine: 7164, EndLine: 7167}}},
		{ID: "has-symbols@1.0.0", Name: "has-symbols", Version: "1.0.0", Locations: []types.Location{{StartLine: 7169, EndLine: 7172}}},
		{ID: "has-to-string-tag-x@1.4.1", Name: "has-to-string-tag-x", Version: "1.4.1", Locations: []types.Location{{StartLine: 7174, EndLine: 7179}}},
		{ID: "has-unicode@2.0.1", Name: "has-unicode", Version: "2.0.1", Locations: []types.Location{{StartLine: 7181, EndLine: 7184}}},
		{ID: "has-value@0.3.1", Name: "has-value", Version: "0.3.1", Locations: []types.Location{{StartLine: 7186, EndLine: 7193}}},
		{ID: "has-value@1.0.0", Name: "has-value", Version: "1.0.0", Locations: []types.Location{{StartLine: 7195, EndLine: 7202}}},
		{ID: "has-values@0.1.4", Name: "has-values", Version: "0.1.4", Locations: []types.Location{{StartLine: 7204, EndLine: 7207}}},
		{ID: "has-values@1.0.0", Name: "has-values", Version: "1.0.0", Locations: []types.Location{{StartLine: 7209, EndLine: 7215}}},
		{ID: "has@1.0.3", Name: "has", Version: "1.0.3", Locations: []types.Location{{StartLine: 7217, EndLine: 7222}}},
		{ID: "hash-base@3.0.4", Name: "hash-base", Version: "3.0.4", Locations: []types.Location{{StartLine: 7224, EndLine: 7230}}},
		{ID: "hash.js@1.1.7", Name: "hash.js", Version: "1.1.7", Locations: []types.Location{{StartLine: 7232, EndLine: 7238}}},
		{ID: "hast-util-from-parse5@5.0.0", Name: "hast-util-from-parse5", Version: "5.0.0", Locations: []types.Location{{StartLine: 7240, EndLine: 7249}}},
		{ID: "hast-util-parse-selector@2.2.1", Name: "hast-util-parse-selector", Version: "2.2.1", Locations: []types.Location{{StartLine: 7251, EndLine: 7254}}},
		{ID: "hastscript@5.0.0", Name: "hastscript", Version: "5.0.0", Locations: []types.Location{{StartLine: 7256, EndLine: 7264}}},
		{ID: "he@1.2.0", Name: "he", Version: "1.2.0", Locations: []types.Location{{StartLine: 7266, EndLine: 7269}}},
		{ID: "history@4.9.0", Name: "history", Version: "4.9.0", Locations: []types.Location{{StartLine: 7271, EndLine: 7281}}},
		{ID: "hmac-drbg@1.0.1", Name: "hmac-drbg", Version: "1.0.1", Locations: []types.Location{{StartLine: 7283, EndLine: 7290}}},
		{ID: "hoist-non-react-statics@1.2.0", Name: "hoist-non-react-statics", Version: "1.2.0", Locations: []types.Location{{StartLine: 7292, EndLine: 7295}}},
		{ID: "hoist-non-react-statics@2.5.5", Name: "hoist-non-react-statics", Version: "2.5.5", Locations: []types.Location{{StartLine: 7297, EndLine: 7300}}},
		{ID: "hoist-non-react-statics@3.3.0", Name: "hoist-non-react-statics", Version: "3.3.0", Locations: []types.Location{{StartLine: 7302, EndLine: 7307}}},
		{ID: "home-or-tmp@2.0.0", Name: "home-or-tmp", Version: "2.0.0", Locations: []types.Location{{StartLine: 7309, EndLine: 7315}}},
		{ID: "homedir-polyfill@1.0.3", Name: "homedir-polyfill", Version: "1.0.3", Locations: []types.Location{{StartLine: 7317, EndLine: 7322}}},
		{ID: "hoopy@0.1.4", Name: "hoopy", Version: "0.1.4", Locations: []types.Location{{StartLine: 7324, EndLine: 7327}}},
		{ID: "hosted-git-info@2.7.1", Name: "hosted-git-info", Version: "2.7.1", Locations: []types.Location{{StartLine: 7329, EndLine: 7332}}},
		{ID: "hpack.js@2.1.6", Name: "hpack.js", Version: "2.1.6", Locations: []types.Location{{StartLine: 7334, EndLine: 7342}}},
		{ID: "html-element-map@1.0.1", Name: "html-element-map", Version: "1.0.1", Locations: []types.Location{{StartLine: 7344, EndLine: 7349}}},
		{ID: "html-encoding-sniffer@1.0.2", Name: "html-encoding-sniffer", Version: "1.0.2", Locations: []types.Location{{StartLine: 7351, EndLine: 7356}}},
		{ID: "html-entities@1.2.1", Name: "html-entities", Version: "1.2.1", Locations: []types.Location{{StartLine: 7358, EndLine: 7361}}},
		{ID: "html-minifier@3.5.21", Name: "html-minifier", Version: "3.5.21", Locations: []types.Location{{StartLine: 7363, EndLine: 7374}}},
		{ID: "html-webpack-harddisk-plugin@1.0.1", Name: "html-webpack-harddisk-plugin", Version: "1.0.1", Locations: []types.Location{{StartLine: 7376, EndLine: 7381}}},
		{ID: "html-webpack-plugin@3.2.0", Name: "html-webpack-plugin", Version: "3.2.0", Locations: []types.Location{{StartLine: 7383, EndLine: 7394}}},
		{ID: "html-webpack-plugin@4.0.0-beta.5", Name: "html-webpack-plugin", Version: "4.0.0-beta.5", Locations: []types.Location{{StartLine: 7396, EndLine: 7406}}},
		{ID: "htmlparser2@3.10.1", Name: "htmlparser2", Version: "3.10.1", Locations: []types.Location{{StartLine: 7408, EndLine: 7418}}},
		{ID: "http-cache-semantics@3.8.1", Name: "http-cache-semantics", Version: "3.8.1", Locations: []types.Location{{StartLine: 7420, EndLine: 7423}}},
		{ID: "http-deceiver@1.2.7", Name: "http-deceiver", Version: "1.2.7", Locations: []types.Location{{StartLine: 7425, EndLine: 7428}}},
		{ID: "http-errors@1.6.3", Name: "http-errors", Version: "1.6.3", Locations: []types.Location{{StartLine: 7430, EndLine: 7438}}},
		{ID: "http-parser-js@0.5.0", Name: "http-parser-js", Version: "0.5.0", Locations: []types.Location{{StartLine: 7440, EndLine: 7443}}},
		{ID: "http-proxy-agent@2.1.0", Name: "http-proxy-agent", Version: "2.1.0", Locations: []types.Location{{StartLine: 7445, EndLine: 7451}}},
		{ID: "http-proxy-middleware@0.19.1", Name: "http-proxy-middleware", Version: "0.19.1", Locations: []types.Location{{StartLine: 7453, EndLine: 7461}}},
		{ID: "http-proxy@1.17.0", Name: "http-proxy", Version: "1.17.0", Locations: []types.Location{{StartLine: 7463, EndLine: 7470}}},
		{ID: "http-signature@1.2.0", Name: "http-signature", Version: "1.2.0", Locations: []types.Location{{StartLine: 7472, EndLine: 7479}}},
		{ID: "https-browserify@1.0.0", Name: "https-browserify", Version: "1.0.0", Locations: []types.Location{{StartLine: 7481, EndLine: 7484}}},
		{ID: "https-proxy-agent@2.2.1", Name: "https-proxy-agent", Version: "2.2.1", Locations: []types.Location{{StartLine: 7486, EndLine: 7492}}},
		{ID: "humanize-ms@1.2.1", Name: "humanize-ms", Version: "1.2.1", Locations: []types.Location{{StartLine: 7494, EndLine: 7499}}},
		{ID: "husky@1.3.1", Name: "husky", Version: "1.3.1", Locations: []types.Location{{StartLine: 7501, EndLine: 7515}}},
		{ID: "hyphenate-style-name@1.0.3", Name: "hyphenate-style-name", Version: "1.0.3", Locations: []types.Location{{StartLine: 7517, EndLine: 7520}}},
		{ID: "i@0.3.6", Name: "i", Version: "0.3.6", Locations: []types.Location{{StartLine: 7522, EndLine: 7525}}},
		{ID: "iconv-lite@0.4.23", Name: "iconv-lite", Version: "0.4.23", Locations: []types.Location{{StartLine: 7527, EndLine: 7532}}},
		{ID: "iconv-lite@0.4.24", Name: "iconv-lite", Version: "0.4.24", Locations: []types.Location{{StartLine: 7534, EndLine: 7539}}},
		{ID: "icss-replace-symbols@1.1.0", Name: "icss-replace-symbols", Version: "1.1.0", Locations: []types.Location{{StartLine: 7541, EndLine: 7544}}},
		{ID: "icss-utils@2.1.0", Name: "icss-utils", Version: "2.1.0", Locations: []types.Location{{StartLine: 7546, EndLine: 7551}}},
		{ID: "ieee754@1.1.13", Name: "ieee754", Version: "1.1.13", Locations: []types.Location{{StartLine: 7553, EndLine: 7556}}},
		{ID: "iferr@0.1.5", Name: "iferr", Version: "0.1.5", Locations: []types.Location{{StartLine: 7558, EndLine: 7561}}},
		{ID: "iferr@1.0.2", Name: "iferr", Version: "1.0.2", Locations: []types.Location{{StartLine: 7563, EndLine: 7566}}},
		{ID: "ignore-walk@3.0.1", Name: "ignore-walk", Version: "3.0.1", Locations: []types.Location{{StartLine: 7568, EndLine: 7573}}},
		{ID: "ignore@3.3.10", Name: "ignore", Version: "3.3.10", Locations: []types.Location{{StartLine: 7575, EndLine: 7578}}},
		{ID: "ignore@4.0.6", Name: "ignore", Version: "4.0.6", Locations: []types.Location{{StartLine: 7580, EndLine: 7583}}},
		{ID: "immer@1.7.2", Name: "immer", Version: "1.7.2", Locations: []types.Location{{StartLine: 7585, EndLine: 7588}}},
		{ID: "immutable@3.8.2", Name: "immutable", Version: "3.8.2", Locations: []types.Location{{StartLine: 7590, EndLine: 7593}}},
		{ID: "import-cwd@2.1.0", Name: "import-cwd", Version: "2.1.0", Locations: []types.Location{{StartLine: 7595, EndLine: 7600}}},
		{ID: "import-fresh@2.0.0", Name: "import-fresh", Version: "2.0.0", Locations: []types.Location{{StartLine: 7602, EndLine: 7608}}},
		{ID: "import-fresh@3.0.0", Name: "import-fresh", Version: "3.0.0", Locations: []types.Location{{StartLine: 7610, EndLine: 7616}}},
		{ID: "import-from@2.1.0", Name: "import-from", Version: "2.1.0", Locations: []types.Location{{StartLine: 7618, EndLine: 7623}}},
		{ID: "import-lazy@2.1.0", Name: "import-lazy", Version: "2.1.0", Locations: []types.Location{{StartLine: 7625, EndLine: 7628}}},
		{ID: "import-local@1.0.0", Name: "import-local", Version: "1.0.0", Locations: []types.Location{{StartLine: 7630, EndLine: 7636}}},
		{ID: "import-local@2.0.0", Name: "import-local", Version: "2.0.0", Locations: []types.Location{{StartLine: 7638, EndLine: 7644}}},
		{ID: "imurmurhash@0.1.4", Name: "imurmurhash", Version: "0.1.4", Locations: []types.Location{{StartLine: 7646, EndLine: 7649}}},
		{ID: "indefinite-observable@1.0.2", Name: "indefinite-observable", Version: "1.0.2", Locations: []types.Location{{StartLine: 7651, EndLine: 7656}}},
		{ID: "indent-string@3.2.0", Name: "indent-string", Version: "3.2.0", Locations: []types.Location{{StartLine: 7658, EndLine: 7661}}},
		{ID: "indexof@0.0.1", Name: "indexof", Version: "0.0.1", Locations: []types.Location{{StartLine: 7663, EndLine: 7666}}},
		{ID: "inflight@1.0.6", Name: "inflight", Version: "1.0.6", Locations: []types.Location{{StartLine: 7668, EndLine: 7674}}},
		{ID: "inherits@2.0.3", Name: "inherits", Version: "2.0.3", Locations: []types.Location{{StartLine: 7676, EndLine: 7679}}},
		{ID: "inherits@2.0.1", Name: "inherits", Version: "2.0.1", Locations: []types.Location{{StartLine: 7681, EndLine: 7684}}},
		{ID: "ini@1.3.5", Name: "ini", Version: "1.3.5", Locations: []types.Location{{StartLine: 7686, EndLine: 7689}}},
		{ID: "init-package-json@1.10.3", Name: "init-package-json", Version: "1.10.3", Locations: []types.Location{{StartLine: 7691, EndLine: 7703}}},
		{ID: "inquirer@6.2.0", Name: "inquirer", Version: "6.2.0", Locations: []types.Location{{StartLine: 7705, EndLine: 7722}}},
		{ID: "inquirer@0.11.4", Name: "inquirer", Version: "0.11.4", Locations: []types.Location{{StartLine: 7724, EndLine: 7741}}},
		{ID: "inquirer@6.3.1", Name: "inquirer", Version: "6.3.1", Locations: []types.Location{{StartLine: 7743, EndLine: 7760}}},
		{ID: "internal-ip@4.3.0", Name: "internal-ip", Version: "4.3.0", Locations: []types.Location{{StartLine: 7762, EndLine: 7768}}},
		{ID: "interpret@1.2.0", Name: "interpret", Version: "1.2.0", Locations: []types.Location{{StartLine: 7770, EndLine: 7773}}},
		{ID: "intl-messageformat-parser@1.4.0", Name: "intl-messageformat-parser", Version: "1.4.0", Locations: []types.Location{{StartLine: 7775, EndLine: 7778}}},
		{ID: "intl-messageformat@2.2.0", Name: "intl-messageformat", Version: "2.2.0", Locations: []types.Location{{StartLine: 7780, EndLine: 7785}}},
		{ID: "intl@1.2.5", Name: "intl", Version: "1.2.5", Locations: []types.Location{{StartLine: 7787, EndLine: 7790}}},
		{ID: "invariant@2.2.4", Name: "invariant", Version: "2.2.4", Locations: []types.Location{{StartLine: 7792, EndLine: 7797}}},
		{ID: "invert-kv@1.0.0", Name: "invert-kv", Version: "1.0.0", Locations: []types.Location{{StartLine: 7799, EndLine: 7802}}},
		{ID: "invert-kv@2.0.0", Name: "invert-kv", Version: "2.0.0", Locations: []types.Location{{StartLine: 7804, EndLine: 7807}}},
		{ID: "ip-regex@2.1.0", Name: "ip-regex", Version: "2.1.0", Locations: []types.Location{{StartLine: 7809, EndLine: 7812}}},
		{ID: "ip@1.1.5", Name: "ip", Version: "1.1.5", Locations: []types.Location{{StartLine: 7814, EndLine: 7817}}},
		{ID: "ipaddr.js@1.9.0", Name: "ipaddr.js", Version: "1.9.0", Locations: []types.Location{{StartLine: 7819, EndLine: 7822}}},
		{ID: "is-accessor-descriptor@0.1.6", Name: "is-accessor-descriptor", Version: "0.1.6", Locations: []types.Location{{StartLine: 7824, EndLine: 7829}}},
		{ID: "is-accessor-descriptor@1.0.0", Name: "is-accessor-descriptor", Version: "1.0.0", Locations: []types.Location{{StartLine: 7831, EndLine: 7836}}},
		{ID: "is-arrayish@0.2.1", Name: "is-arrayish", Version: "0.2.1", Locations: []types.Location{{StartLine: 7838, EndLine: 7841}}},
		{ID: "is-binary-path@1.0.1", Name: "is-binary-path", Version: "1.0.1", Locations: []types.Location{{StartLine: 7843, EndLine: 7848}}},
		{ID: "is-boolean-object@1.0.0", Name: "is-boolean-object", Version: "1.0.0", Locations: []types.Location{{StartLine: 7850, EndLine: 7853}}},
		{ID: "is-buffer@1.1.6", Name: "is-buffer", Version: "1.1.6", Locations: []types.Location{{StartLine: 7855, EndLine: 7858}}},
		{ID: "is-buffer@2.0.3", Name: "is-buffer", Version: "2.0.3", Locations: []types.Location{{StartLine: 7860, EndLine: 7863}}},
		{ID: "is-callable@1.1.4", Name: "is-callable", Version: "1.1.4", Locations: []types.Location{{StartLine: 7865, EndLine: 7868}}},
		{ID: "is-ci@1.2.1", Name: "is-ci", Version: "1.2.1", Locations: []types.Location{{StartLine: 7870, EndLine: 7875}}},
		{ID: "is-ci@2.0.0", Name: "is-ci", Version: "2.0.0", Locations: []types.Location{{StartLine: 7877, EndLine: 7882}}},
		{ID: "is-cidr@3.0.0", Name: "is-cidr", Version: "3.0.0", Locations: []types.Location{{StartLine: 7884, EndLine: 7889}}},
		{ID: "is-data-descriptor@0.1.4", Name: "is-data-descriptor", Version: "0.1.4", Locations: []types.Location{{StartLine: 7891, EndLine: 7896}}},
		{ID: "is-data-descriptor@1.0.0", Name: "is-data-descriptor", Version: "1.0.0", Locations: []types.Location{{StartLine: 7898, EndLine: 7903}}},
		{ID: "is-date-object@1.0.1", Name: "is-date-object", Version: "1.0.1", Locations: []types.Location{{StartLine: 7905, EndLine: 7908}}},
		{ID: "is-descriptor@0.1.6", Name: "is-descriptor", Version: "0.1.6", Locations: []types.Location{{StartLine: 7910, EndLine: 7917}}},
		{ID: "is-descriptor@1.0.2", Name: "is-descriptor", Version: "1.0.2", Locations: []types.Location{{StartLine: 7919, EndLine: 7926}}},
		{ID: "is-directory@0.3.1", Name: "is-directory", Version: "0.3.1", Locations: []types.Location{{StartLine: 7928, EndLine: 7931}}},
		{ID: "is-dom@1.0.9", Name: "is-dom", Version: "1.0.9", Locations: []types.Location{{StartLine: 7933, EndLine: 7936}}},
		{ID: "is-dotfile@1.0.3", Name: "is-dotfile", Version: "1.0.3", Locations: []types.Location{{StartLine: 7938, EndLine: 7941}}},
		{ID: "is-electron@2.2.0", Name: "is-electron", Version: "2.2.0", Locations: []types.Location{{StartLine: 7943, EndLine: 7946}}},
		{ID: "is-equal-shallow@0.1.3", Name: "is-equal-shallow", Version: "0.1.3", Locations: []types.Location{{StartLine: 7948, EndLine: 7953}}},
		{ID: "is-extendable@0.1.1", Name: "is-extendable", Version: "0.1.1", Locations: []types.Location{{StartLine: 7955, EndLine: 7958}}},
		{ID: "is-extendable@1.0.1", Name: "is-extendable", Version: "1.0.1", Locations: []types.Location{{StartLine: 7960, EndLine: 7965}}},
		{ID: "is-extglob@1.0.0", Name: "is-extglob", Version: "1.0.0", Locations: []types.Location{{StartLine: 7967, EndLine: 7970}}},
		{ID: "is-extglob@2.1.1", Name: "is-extglob", Version: "2.1.1", Locations: []types.Location{{StartLine: 7972, EndLine: 7975}}},
		{ID: "is-finite@1.0.2", Name: "is-finite", Version: "1.0.2", Locations: []types.Location{{StartLine: 7977, EndLine: 7982}}},
		{ID: "is-fullwidth-code-point@1.0.0", Name: "is-fullwidth-code-point", Version: "1.0.0", Locations: []types.Location{{StartLine: 7984, EndLine: 7989}}},
		{ID: "is-fullwidth-code-point@2.0.0", Name: "is-fullwidth-code-point", Version: "2.0.0", Locations: []types.Location{{StartLine: 7991, EndLine: 7994}}},
		{ID: "is-generator-fn@1.0.0", Name: "is-generator-fn", Version: "1.0.0", Locations: []types.Location{{StartLine: 7996, EndLine: 7999}}},
		{ID: "is-glob@2.0.1", Name: "is-glob", Version: "2.0.1", Locations: []types.Location{{StartLine: 8001, EndLine: 8006}}},
		{ID: "is-glob@3.1.0", Name: "is-glob", Version: "3.1.0", Locations: []types.Location{{StartLine: 8008, EndLine: 8013}}},
		{ID: "is-glob@4.0.1", Name: "is-glob", Version: "4.0.1", Locations: []types.Location{{StartLine: 8015, EndLine: 8020}}},
		{ID: "is-in-browser@1.1.3", Name: "is-in-browser", Version: "1.1.3", Locations: []types.Location{{StartLine: 8022, EndLine: 8025}}},
		{ID: "is-installed-globally@0.1.0", Name: "is-installed-globally", Version: "0.1.0", Locations: []types.Location{{StartLine: 8027, EndLine: 8033}}},
		{ID: "is-npm@1.0.0", Name: "is-npm", Version: "1.0.0", Locations: []types.Location{{StartLine: 8035, EndLine: 8038}}},
		{ID: "is-number-object@1.0.3", Name: "is-number-object", Version: "1.0.3", Locations: []types.Location{{StartLine: 8040, EndLine: 8043}}},
		{ID: "is-number@2.1.0", Name: "is-number", Version: "2.1.0", Locations: []types.Location{{StartLine: 8045, EndLine: 8050}}},
		{ID: "is-number@3.0.0", Name: "is-number", Version: "3.0.0", Locations: []types.Location{{StartLine: 8052, EndLine: 8057}}},
		{ID: "is-number@4.0.0", Name: "is-number", Version: "4.0.0", Locations: []types.Location{{StartLine: 8059, EndLine: 8062}}},
		{ID: "is-obj@1.0.1", Name: "is-obj", Version: "1.0.1", Locations: []types.Location{{StartLine: 8064, EndLine: 8067}}},
		{ID: "is-object@1.0.1", Name: "is-object", Version: "1.0.1", Locations: []types.Location{{StartLine: 8069, EndLine: 8072}}},
		{ID: "is-observable@1.1.0", Name: "is-observable", Version: "1.1.0", Locations: []types.Location{{StartLine: 8074, EndLine: 8079}}},
		{ID: "is-path-cwd@1.0.0", Name: "is-path-cwd", Version: "1.0.0", Locations: []types.Location{{StartLine: 8081, EndLine: 8084}}},
		{ID: "is-path-cwd@2.1.0", Name: "is-path-cwd", Version: "2.1.0", Locations: []types.Location{{StartLine: 8086, EndLine: 8089}}},
		{ID: "is-path-in-cwd@1.0.1", Name: "is-path-in-cwd", Version: "1.0.1", Locations: []types.Location{{StartLine: 8091, EndLine: 8096}}},
		{ID: "is-path-in-cwd@2.1.0", Name: "is-path-in-cwd", Version: "2.1.0", Locations: []types.Location{{StartLine: 8098, EndLine: 8103}}},
		{ID: "is-path-inside@1.0.1", Name: "is-path-inside", Version: "1.0.1", Locations: []types.Location{{StartLine: 8105, EndLine: 8110}}},
		{ID: "is-path-inside@2.1.0", Name: "is-path-inside", Version: "2.1.0", Locations: []types.Location{{StartLine: 8112, EndLine: 8117}}},
		{ID: "is-plain-obj@1.1.0", Name: "is-plain-obj", Version: "1.1.0", Locations: []types.Location{{StartLine: 8119, EndLine: 8122}}},
		{ID: "is-plain-object@2.0.4", Name: "is-plain-object", Version: "2.0.4", Locations: []types.Location{{StartLine: 8124, EndLine: 8129}}},
		{ID: "is-posix-bracket@0.1.1", Name: "is-posix-bracket", Version: "0.1.1", Locations: []types.Location{{StartLine: 8131, EndLine: 8134}}},
		{ID: "is-primitive@2.0.0", Name: "is-primitive", Version: "2.0.0", Locations: []types.Location{{StartLine: 8136, EndLine: 8139}}},
		{ID: "is-promise@2.1.0", Name: "is-promise", Version: "2.1.0", Locations: []types.Location{{StartLine: 8141, EndLine: 8144}}},
		{ID: "is-redirect@1.0.0", Name: "is-redirect", Version: "1.0.0", Locations: []types.Location{{StartLine: 8146, EndLine: 8149}}},
		{ID: "is-regex@1.0.4", Name: "is-regex", Version: "1.0.4", Locations: []types.Location{{StartLine: 8151, EndLine: 8156}}},
		{ID: "is-regexp@1.0.0", Name: "is-regexp", Version: "1.0.0", Locations: []types.Location{{StartLine: 8158, EndLine: 8161}}},
		{ID: "is-retry-allowed@1.1.0", Name: "is-retry-allowed", Version: "1.1.0", Locations: []types.Location{{StartLine: 8163, EndLine: 8166}}},
		{ID: "is-root@2.0.0", Name: "is-root", Version: "2.0.0", Locations: []types.Location{{StartLine: 8168, EndLine: 8171}}},
		{ID: "is-stream@1.1.0", Name: "is-stream", Version: "1.1.0", Locations: []types.Location{{StartLine: 8173, EndLine: 8176}}},
		{ID: "is-string@1.0.4", Name: "is-string", Version: "1.0.4", Locations: []types.Location{{StartLine: 8178, EndLine: 8181}}},
		{ID: "is-subset@0.1.1", Name: "is-subset", Version: "0.1.1", Locations: []types.Location{{StartLine: 8183, EndLine: 8186}}},
		{ID: "is-symbol@1.0.2", Name: "is-symbol", Version: "1.0.2", Locations: []types.Location{{StartLine: 8188, EndLine: 8193}}},
		{ID: "is-typedarray@1.0.0", Name: "is-typedarray", Version: "1.0.0", Locations: []types.Location{{StartLine: 8195, EndLine: 8198}}},
		{ID: "is-utf8@0.2.1", Name: "is-utf8", Version: "0.2.1", Locations: []types.Location{{StartLine: 8200, EndLine: 8203}}},
		{ID: "is-windows@1.0.2", Name: "is-windows", Version: "1.0.2", Locations: []types.Location{{StartLine: 8205, EndLine: 8208}}},
		{ID: "is-wsl@1.1.0", Name: "is-wsl", Version: "1.1.0", Locations: []types.Location{{StartLine: 8210, EndLine: 8213}}},
		{ID: "isarray@0.0.1", Name: "isarray", Version: "0.0.1", Locations: []types.Location{{StartLine: 8215, EndLine: 8218}}},
		{ID: "isarray@1.0.0", Name: "isarray", Version: "1.0.0", Locations: []types.Location{{StartLine: 8220, EndLine: 8223}}},
		{ID: "isarray@2.0.1", Name: "isarray", Version: "2.0.1", Locations: []types.Location{{StartLine: 8225, EndLine: 8228}}},
		{ID: "isexe@2.0.0", Name: "isexe", Version: "2.0.0", Locations: []types.Location{{StartLine: 8230, EndLine: 8233}}},
		{ID: "isobject@2.1.0", Name: "isobject", Version: "2.1.0", Locations: []types.Location{{StartLine: 8235, EndLine: 8240}}},
		{ID: "isobject@3.0.1", Name: "isobject", Version: "3.0.1", Locations: []types.Location{{StartLine: 8242, EndLine: 8245}}},
		{ID: "isomorphic-fetch@2.2.1", Name: "isomorphic-fetch", Version: "2.2.1", Locations: []types.Location{{StartLine: 8247, EndLine: 8253}}},
		{ID: "isstream@0.1.2", Name: "isstream", Version: "0.1.2", Locations: []types.Location{{StartLine: 8255, EndLine: 8258}}},
		{ID: "istanbul-api@1.3.7", Name: "istanbul-api", Version: "1.3.7", Locations: []types.Location{{StartLine: 8260, EndLine: 8275}}},
		{ID: "istanbul-lib-coverage@1.2.1", Name: "istanbul-lib-coverage", Version: "1.2.1", Locations: []types.Location{{StartLine: 8277, EndLine: 8280}}},
		{ID: "istanbul-lib-hook@1.2.2", Name: "istanbul-lib-hook", Version: "1.2.2", Locations: []types.Location{{StartLine: 8282, EndLine: 8287}}},
		{ID: "istanbul-lib-instrument@1.10.2", Name: "istanbul-lib-instrument", Version: "1.10.2", Locations: []types.Location{{StartLine: 8289, EndLine: 8300}}},
		{ID: "istanbul-lib-report@1.1.5", Name: "istanbul-lib-report", Version: "1.1.5", Locations: []types.Location{{StartLine: 8302, EndLine: 8310}}},
		{ID: "istanbul-lib-source-maps@1.2.6", Name: "istanbul-lib-source-maps", Version: "1.2.6", Locations: []types.Location{{StartLine: 8312, EndLine: 8321}}},
		{ID: "istanbul-reports@1.5.1", Name: "istanbul-reports", Version: "1.5.1", Locations: []types.Location{{StartLine: 8323, EndLine: 8328}}},
		{ID: "isurl@1.0.0", Name: "isurl", Version: "1.0.0", Locations: []types.Location{{StartLine: 8330, EndLine: 8336}}},
		{ID: "jest-changed-files@23.4.2", Name: "jest-changed-files", Version: "23.4.2", Locations: []types.Location{{StartLine: 8338, EndLine: 8343}}},
		{ID: "jest-cli@23.6.0", Name: "jest-cli", Version: "23.6.0", Locations: []types.Location{{StartLine: 8345, EndLine: 8385}}},
		{ID: "jest-config@23.6.0", Name: "jest-config", Version: "23.6.0", Locations: []types.Location{{StartLine: 8387, EndLine: 8405}}},
		{ID: "jest-diff@23.6.0", Name: "jest-diff", Version: "23.6.0", Locations: []types.Location{{StartLine: 8407, EndLine: 8415}}},
		{ID: "jest-docblock@23.2.0", Name: "jest-docblock", Version: "23.2.0", Locations: []types.Location{{StartLine: 8417, EndLine: 8422}}},
		{ID: "jest-each@23.6.0", Name: "jest-each", Version: "23.6.0", Locations: []types.Location{{StartLine: 8424, EndLine: 8430}}},
		{ID: "jest-environment-jsdom@23.4.0", Name: "jest-environment-jsdom", Version: "23.4.0", Locations: []types.Location{{StartLine: 8432, EndLine: 8439}}},
		{ID: "jest-environment-node@23.4.0", Name: "jest-environment-node", Version: "23.4.0", Locations: []types.Location{{StartLine: 8441, EndLine: 8447}}},
		{ID: "jest-get-type@22.4.3", Name: "jest-get-type", Version: "22.4.3", Locations: []types.Location{{StartLine: 8449, EndLine: 8452}}},
		{ID: "jest-haste-map@23.6.0", Name: "jest-haste-map", Version: "23.6.0", Locations: []types.Location{{StartLine: 8454, EndLine: 8466}}},
		{ID: "jest-jasmine2@23.6.0", Name: "jest-jasmine2", Version: "23.6.0", Locations: []types.Location{{StartLine: 8468, EndLine: 8484}}},
		{ID: "jest-leak-detector@23.6.0", Name: "jest-leak-detector", Version: "23.6.0", Locations: []types.Location{{StartLine: 8486, EndLine: 8491}}},
		{ID: "jest-matcher-utils@23.6.0", Name: "jest-matcher-utils", Version: "23.6.0", Locations: []types.Location{{StartLine: 8493, EndLine: 8500}}},
		{ID: "jest-message-util@23.4.0", Name: "jest-message-util", Version: "23.4.0", Locations: []types.Location{{StartLine: 8502, EndLine: 8511}}},
		{ID: "jest-mock@23.2.0", Name: "jest-mock", Version: "23.2.0", Locations: []types.Location{{StartLine: 8513, EndLine: 8516}}},
		{ID: "jest-regex-util@23.3.0", Name: "jest-regex-util", Version: "23.3.0", Locations: []types.Location{{StartLine: 8518, EndLine: 8521}}},
		{ID: "jest-resolve-dependencies@23.6.0", Name: "jest-resolve-dependencies", Version: "23.6.0", Locations: []types.Location{{StartLine: 8523, EndLine: 8529}}},
		{ID: "jest-resolve@23.6.0", Name: "jest-resolve", Version: "23.6.0", Locations: []types.Location{{StartLine: 8531, EndLine: 8538}}},
		{ID: "jest-runner@23.6.0", Name: "jest-runner", Version: "23.6.0", Locations: []types.Location{{StartLine: 8540, EndLine: 8557}}},
		{ID: "jest-runtime@23.6.0", Name: "jest-runtime", Version: "23.6.0", Locations: []types.Location{{StartLine: 8559, EndLine: 8584}}},
		{ID: "jest-serializer@23.0.1", Name: "jest-serializer", Version: "23.0.1", Locations: []types.Location{{StartLine: 8586, EndLine: 8589}}},
		{ID: "jest-snapshot@23.6.0", Name: "jest-snapshot", Version: "23.6.0", Locations: []types.Location{{StartLine: 8591, EndLine: 8605}}},
		{ID: "jest-util@23.4.0", Name: "jest-util", Version: "23.4.0", Locations: []types.Location{{StartLine: 8607, EndLine: 8619}}},
		{ID: "jest-validate@23.6.0", Name: "jest-validate", Version: "23.6.0", Locations: []types.Location{{StartLine: 8621, EndLine: 8629}}},
		{ID: "jest-watcher@23.4.0", Name: "jest-watcher", Version: "23.4.0", Locations: []types.Location{{StartLine: 8631, EndLine: 8638}}},
		{ID: "jest-worker@23.2.0", Name: "jest-worker", Version: "23.2.0", Locations: []types.Location{{StartLine: 8640, EndLine: 8645}}},
		{ID: "jest@23.6.0", Name: "jest", Version: "23.6.0", Locations: []types.Location{{StartLine: 8647, EndLine: 8653}}},
		{ID: "js-file-download@0.4.5", Name: "js-file-download", Version: "0.4.5", Locations: []types.Location{{StartLine: 8655, EndLine: 8658}}},
		{ID: "js-levenshtein@1.1.6", Name: "js-levenshtein", Version: "1.1.6", Locations: []types.Location{{StartLine: 8660, EndLine: 8663}}},
		{ID: "js-tokens@3.0.2", Name: "js-tokens", Version: "3.0.2", Locations: []types.Location{{StartLine: 8665, EndLine: 8668}}},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Locations: []types.Location{{StartLine: 8670, EndLine: 8673}}},
		{ID: "js-yaml@3.13.1", Name: "js-yaml", Version: "3.13.1", Locations: []types.Location{{StartLine: 8675, EndLine: 8681}}},
		{ID: "jsbn@0.1.1", Name: "jsbn", Version: "0.1.1", Locations: []types.Location{{StartLine: 8683, EndLine: 8686}}},
		{ID: "jscodeshift@0.5.1", Name: "jscodeshift", Version: "0.5.1", Locations: []types.Location{{StartLine: 8688, EndLine: 8707}}},
		{ID: "jsdom@11.12.0", Name: "jsdom", Version: "11.12.0", Locations: []types.Location{{StartLine: 8709, EndLine: 8739}}},
		{ID: "jsesc@1.3.0", Name: "jsesc", Version: "1.3.0", Locations: []types.Location{{StartLine: 8741, EndLine: 8744}}},
		{ID: "jsesc@2.5.2", Name: "jsesc", Version: "2.5.2", Locations: []types.Location{{StartLine: 8746, EndLine: 8749}}},
		{ID: "jsesc@0.5.0", Name: "jsesc", Version: "0.5.0", Locations: []types.Location{{StartLine: 8751, EndLine: 8754}}},
		{ID: "json-parse-better-errors@1.0.2", Name: "json-parse-better-errors", Version: "1.0.2", Locations: []types.Location{{StartLine: 8756, EndLine: 8759}}},
		{ID: "json-schema-traverse@0.4.1", Name: "json-schema-traverse", Version: "0.4.1", Locations: []types.Location{{StartLine: 8761, EndLine: 8764}}},
		{ID: "json-schema@0.2.3", Name: "json-schema", Version: "0.2.3", Locations: []types.Location{{StartLine: 8766, EndLine: 8769}}},
		{ID: "json-stable-stringify-without-jsonify@1.0.1", Name: "json-stable-stringify-without-jsonify", Version: "1.0.1", Locations: []types.Location{{StartLine: 8771, EndLine: 8774}}},
		{ID: "json-stringify-safe@5.0.1", Name: "json-stringify-safe", Version: "5.0.1", Locations: []types.Location{{StartLine: 8776, EndLine: 8779}}},
		{ID: "json3@3.3.2", Name: "json3", Version: "3.3.2", Locations: []types.Location{{StartLine: 8781, EndLine: 8784}}},
		{ID: "json5@0.5.1", Name: "json5", Version: "0.5.1", Locations: []types.Location{{StartLine: 8786, EndLine: 8789}}},
		{ID: "json5@1.0.1", Name: "json5", Version: "1.0.1", Locations: []types.Location{{StartLine: 8791, EndLine: 8796}}},
		{ID: "json5@2.1.0", Name: "json5", Version: "2.1.0", Locations: []types.Location{{StartLine: 8798, EndLine: 8803}}},
		{ID: "jsonfile@2.4.0", Name: "jsonfile", Version: "2.4.0", Locations: []types.Location{{StartLine: 8805, EndLine: 8810}}},
		{ID: "jsonfile@4.0.0", Name: "jsonfile", Version: "4.0.0", Locations: []types.Location{{StartLine: 8812, EndLine: 8817}}},
		{ID: "jsonify@0.0.0", Name: "jsonify", Version: "0.0.0", Locations: []types.Location{{StartLine: 8819, EndLine: 8822}}},
		{ID: "jsonparse@1.3.1", Name: "jsonparse", Version: "1.3.1", Locations: []types.Location{{StartLine: 8824, EndLine: 8827}}},
		{ID: "jsprim@1.4.1", Name: "jsprim", Version: "1.4.1", Locations: []types.Location{{StartLine: 8829, EndLine: 8837}}},
		{ID: "jss-camel-case@6.1.0", Name: "jss-camel-case", Version: "6.1.0", Locations: []types.Location{{StartLine: 8839, EndLine: 8844}}},
		{ID: "jss-default-unit@8.0.2", Name: "jss-default-unit", Version: "8.0.2", Locations: []types.Location{{StartLine: 8846, EndLine: 8849}}},
		{ID: "jss-global@3.0.0", Name: "jss-global", Version: "3.0.0", Locations: []types.Location{{StartLine: 8851, EndLine: 8854}}},
		{ID: "jss-nested@6.0.1", Name: "jss-nested", Version: "6.0.1", Locations: []types.Location{{StartLine: 8856, EndLine: 8861}}},
		{ID: "jss-props-sort@6.0.0", Name: "jss-props-sort", Version: "6.0.0", Locations: []types.Location{{StartLine: 8863, EndLine: 8866}}},
		{ID: "jss-vendor-prefixer@7.0.0", Name: "jss-vendor-prefixer", Version: "7.0.0", Locations: []types.Location{{StartLine: 8868, EndLine: 8873}}},
		{ID: "jss@9.8.7", Name: "jss", Version: "9.8.7", Locations: []types.Location{{StartLine: 8875, EndLine: 8882}}},
		{ID: "jsx-ast-utils@2.1.0", Name: "jsx-ast-utils", Version: "2.1.0", Locations: []types.Location{{StartLine: 8884, EndLine: 8889}}},
		{ID: "keycode@2.2.0", Name: "keycode", Version: "2.2.0", Locations: []types.Location{{StartLine: 8891, EndLine: 8894}}},
		{ID: "killable@1.0.1", Name: "killable", Version: "1.0.1", Locations: []types.Location{{StartLine: 8896, EndLine: 8899}}},
		{ID: "kind-of@2.0.1", Name: "kind-of", Version: "2.0.1", Locations: []types.Location{{StartLine: 8901, EndLine: 8906}}},
		{ID: "kind-of@3.2.2", Name: "kind-of", Version: "3.2.2", Locations: []types.Location{{StartLine: 8908, EndLine: 8913}}},
		{ID: "kind-of@4.0.0", Name: "kind-of", Version: "4.0.0", Locations: []types.Location{{StartLine: 8915, EndLine: 8920}}},
		{ID: "kind-of@5.1.0", Name: "kind-of", Version: "5.1.0", Locations: []types.Location{{StartLine: 8922, EndLine: 8925}}},
		{ID: "kind-of@6.0.2", Name: "kind-of", Version: "6.0.2", Locations: []types.Location{{StartLine: 8927, EndLine: 8930}}},
		{ID: "klaw@1.3.1", Name: "klaw", Version: "1.3.1", Locations: []types.Location{{StartLine: 8932, EndLine: 8937}}},
		{ID: "kleur@2.0.2", Name: "kleur", Version: "2.0.2", Locations: []types.Location{{StartLine: 8939, EndLine: 8942}}},
		{ID: "latest-version@3.1.0", Name: "latest-version", Version: "3.1.0", Locations: []types.Location{{StartLine: 8944, EndLine: 8949}}},
		{ID: "lazy-cache@0.2.7", Name: "lazy-cache", Version: "0.2.7", Locations: []types.Location{{StartLine: 8951, EndLine: 8954}}},
		{ID: "lazy-cache@1.0.4", Name: "lazy-cache", Version: "1.0.4", Locations: []types.Location{{StartLine: 8956, EndLine: 8959}}},
		{ID: "lazy-property@1.0.0", Name: "lazy-property", Version: "1.0.0", Locations: []types.Location{{StartLine: 8961, EndLine: 8964}}},
		{ID: "lazy-universal-dotenv@2.0.0", Name: "lazy-universal-dotenv", Version: "2.0.0", Locations: []types.Location{{StartLine: 8966, EndLine: 8975}}},
		{ID: "lcid@1.0.0", Name: "lcid", Version: "1.0.0", Locations: []types.Location{{StartLine: 8977, EndLine: 8982}}},
		{ID: "lcid@2.0.0", Name: "lcid", Version: "2.0.0", Locations: []types.Location{{StartLine: 8984, EndLine: 8989}}},
		{ID: "left-pad@1.3.0", Name: "left-pad", Version: "1.3.0", Locations: []types.Location{{StartLine: 8991, EndLine: 8994}}},
		{ID: "leven@2.1.0", Name: "leven", Version: "2.1.0", Locations: []types.Location{{StartLine: 8996, EndLine: 8999}}},
		{ID: "levn@0.3.0", Name: "levn", Version: "0.3.0", Locations: []types.Location{{StartLine: 9001, EndLine: 9007}}},
		{ID: "libcipm@3.0.3", Name: "libcipm", Version: "3.0.3", Locations: []types.Location{{StartLine: 9009, EndLine: 9028}}},
		{ID: "libnpm@2.0.1", Name: "libnpm", Version: "2.0.1", Locations: []types.Location{{StartLine: 9030, EndLine: 9054}}},
		{ID: "libnpmaccess@3.0.1", Name: "libnpmaccess", Version: "3.0.1", Locations: []types.Location{{StartLine: 9056, EndLine: 9064}}},
		{ID: "libnpmconfig@1.2.1", Name: "libnpmconfig", Version: "1.2.1", Locations: []types.Location{{StartLine: 9066, EndLine: 9073}}},
		{ID: "libnpmhook@5.0.2", Name: "libnpmhook", Version: "5.0.2", Locations: []types.Location{{StartLine: 9075, EndLine: 9083}}},
		{ID: "libnpmorg@1.0.0", Name: "libnpmorg", Version: "1.0.0", Locations: []types.Location{{StartLine: 9085, EndLine: 9093}}},
		{ID: "libnpmpublish@1.1.1", Name: "libnpmpublish", Version: "1.1.1", Locations: []types.Location{{StartLine: 9095, EndLine: 9108}}},
		{ID: "libnpmsearch@2.0.0", Name: "libnpmsearch", Version: "2.0.0", Locations: []types.Location{{StartLine: 9110, EndLine: 9117}}},
		{ID: "libnpmteam@1.0.1", Name: "libnpmteam", Version: "1.0.1", Locations: []types.Location{{StartLine: 9119, EndLine: 9127}}},
		{ID: "libnpx@10.2.0", Name: "libnpx", Version: "10.2.0", Locations: []types.Location{{StartLine: 9129, EndLine: 9141}}},
		{ID: "linear-layout-vector@0.0.1", Name: "linear-layout-vector", Version: "0.0.1", Locations: []types.Location{{StartLine: 9143, EndLine: 9146}}},
		{ID: "lint-staged@7.3.0", Name: "lint-staged", Version: "7.3.0", Locations: []types.Location{{StartLine: 9148, EndLine: 9174}}},
		{ID: "listenercount@1.0.1", Name: "listenercount", Version: "1.0.1", Locations: []types.Location{{StartLine: 9176, EndLine: 9179}}},
		{ID: "listr-silent-renderer@1.1.1", Name: "listr-silent-renderer", Version: "1.1.1", Locations: []types.Location{{StartLine: 9181, EndLine: 9184}}},
		{ID: "listr-update-renderer@0.5.0", Name: "listr-update-renderer", Version: "0.5.0", Locations: []types.Location{{StartLine: 9186, EndLine: 9198}}},
		{ID: "listr-verbose-renderer@0.5.0", Name: "listr-verbose-renderer", Version: "0.5.0", Locations: []types.Location{{StartLine: 9200, EndLine: 9208}}},
		{ID: "listr@0.14.3", Name: "listr", Version: "0.14.3", Locations: []types.Location{{StartLine: 9210, EndLine: 9223}}},
		{ID: "load-json-file@1.1.0", Name: "load-json-file", Version: "1.1.0", Locations: []types.Location{{StartLine: 9225, EndLine: 9234}}},
		{ID: "load-json-file@2.0.0", Name: "load-json-file", Version: "2.0.0", Locations: []types.Location{{StartLine: 9236, EndLine: 9244}}},
		{ID: "load-json-file@4.0.0", Name: "load-json-file", Version: "4.0.0", Locations: []types.Location{{StartLine: 9246, EndLine: 9254}}},
		{ID: "load-script@1.0.0", Name: "load-script", Version: "1.0.0", Locations: []types.Location{{StartLine: 9256, EndLine: 9259}}},
		{ID: "loader-fs-cache@1.0.2", Name: "loader-fs-cache", Version: "1.0.2", Locations: []types.Location{{StartLine: 9261, EndLine: 9267}}},
		{ID: "loader-runner@2.4.0", Name: "loader-runner", Version: "2.4.0", Locations: []types.Location{{StartLine: 9269, EndLine: 9272}}},
		{ID: "loader-utils@1.1.0", Name: "loader-utils", Version: "1.1.0", Locations: []types.Location{{StartLine: 9274, EndLine: 9281}}},
		{ID: "loader-utils@0.2.17", Name: "loader-utils", Version: "0.2.17", Locations: []types.Location{{StartLine: 9283, EndLine: 9291}}},
		{ID: "loader-utils@1.2.3", Name: "loader-utils", Version: "1.2.3", Locations: []types.Location{{StartLine: 9293, EndLine: 9300}}},
		{ID: "locate-path@2.0.0", Name: "locate-path", Version: "2.0.0", Locations: []types.Location{{StartLine: 9302, EndLine: 9308}}},
		{ID: "locate-path@3.0.0", Name: "locate-path", Version: "3.0.0", Locations: []types.Location{{StartLine: 9310, EndLine: 9316}}},
		{ID: "lock-verify@2.1.0", Name: "lock-verify", Version: "2.1.0", Locations: []types.Location{{StartLine: 9318, EndLine: 9324}}},
		{ID: "lockfile@1.0.4", Name: "lockfile", Version: "1.0.4", Locations: []types.Location{{StartLine: 9326, EndLine: 9331}}},
		{ID: "lodash-es@4.17.11", Name: "lodash-es", Version: "4.17.11", Locations: []types.Location{{StartLine: 9333, EndLine: 9336}}},
		{ID: "lodash._baseuniq@4.6.0", Name: "lodash._baseuniq", Version: "4.6.0", Locations: []types.Location{{StartLine: 9338, EndLine: 9344}}},
		{ID: "lodash._createset@4.0.3", Name: "lodash._createset", Version: "4.0.3", Locations: []types.Location{{StartLine: 9346, EndLine: 9349}}},
		{ID: "lodash._root@3.0.1", Name: "lodash._root", Version: "3.0.1", Locations: []types.Location{{StartLine: 9351, EndLine: 9354}}},
		{ID: "lodash.assign@4.2.0", Name: "lodash.assign", Version: "4.2.0", Locations: []types.Location{{StartLine: 9356, EndLine: 9359}}},
		{ID: "lodash.clonedeep@4.5.0", Name: "lodash.clonedeep", Version: "4.5.0", Locations: []types.Location{{StartLine: 9361, EndLine: 9364}}},
		{ID: "lodash.escape@4.0.1", Name: "lodash.escape", Version: "4.0.1", Locations: []types.Location{{StartLine: 9366, EndLine: 9369}}},
		{ID: "lodash.flattendeep@4.4.0", Name: "lodash.flattendeep", Version: "4.4.0", Locations: []types.Location{{StartLine: 9371, EndLine: 9374}}},
		{ID: "lodash.isequal@4.5.0", Name: "lodash.isequal", Version: "4.5.0", Locations: []types.Location{{StartLine: 9376, EndLine: 9379}}},
		{ID: "lodash.isplainobject@4.0.6", Name: "lodash.isplainobject", Version: "4.0.6", Locations: []types.Location{{StartLine: 9381, EndLine: 9384}}},
		{ID: "lodash.merge@4.6.1", Name: "lodash.merge", Version: "4.6.1", Locations: []types.Location{{StartLine: 9386, EndLine: 9389}}},
		{ID: "lodash.some@4.6.0", Name: "lodash.some", Version: "4.6.0", Locations: []types.Location{{StartLine: 9391, EndLine: 9394}}},
		{ID: "lodash.sortby@4.7.0", Name: "lodash.sortby", Version: "4.7.0", Locations: []types.Location{{StartLine: 9396, EndLine: 9399}}},
		{ID: "lodash.union@4.6.0", Name: "lodash.union", Version: "4.6.0", Locations: []types.Location{{StartLine: 9401, EndLine: 9404}}},
		{ID: "lodash.uniq@4.5.0", Name: "lodash.uniq", Version: "4.5.0", Locations: []types.Location{{StartLine: 9406, EndLine: 9409}}},
		{ID: "lodash.without@4.4.0", Name: "lodash.without", Version: "4.4.0", Locations: []types.Location{{StartLine: 9411, EndLine: 9414}}},
		{ID: "lodash@4.17.11", Name: "lodash", Version: "4.17.11", Locations: []types.Location{{StartLine: 9416, EndLine: 9419}}},
		{ID: "lodash@3.10.1", Name: "lodash", Version: "3.10.1", Locations: []types.Location{{StartLine: 9421, EndLine: 9424}}},
		{ID: "log-symbols@1.0.2", Name: "log-symbols", Version: "1.0.2", Locations: []types.Location{{StartLine: 9426, EndLine: 9431}}},
		{ID: "log-symbols@2.2.0", Name: "log-symbols", Version: "2.2.0", Locations: []types.Location{{StartLine: 9433, EndLine: 9438}}},
		{ID: "log-update@2.3.0", Name: "log-update", Version: "2.3.0", Locations: []types.Location{{StartLine: 9440, EndLine: 9447}}},
		{ID: "loglevel@1.6.1", Name: "loglevel", Version: "1.6.1", Locations: []types.Location{{StartLine: 9449, EndLine: 9452}}},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Locations: []types.Location{{StartLine: 9454, EndLine: 9459}}},
		{ID: "lower-case@1.1.4", Name: "lower-case", Version: "1.1.4", Locations: []types.Location{{StartLine: 9461, EndLine: 9464}}},
		{ID: "lowercase-keys@1.0.1", Name: "lowercase-keys", Version: "1.0.1", Locations: []types.Location{{StartLine: 9466, EndLine: 9469}}},
		{ID: "lru-cache@4.1.5", Name: "lru-cache", Version: "4.1.5", Locations: []types.Location{{StartLine: 9471, EndLine: 9477}}},
		{ID: "lru-cache@5.1.1", Name: "lru-cache", Version: "5.1.1", Locations: []types.Location{{StartLine: 9479, EndLine: 9484}}},
		{ID: "macos-release@2.2.0", Name: "macos-release", Version: "2.2.0", Locations: []types.Location{{StartLine: 9486, EndLine: 9489}}},
		{ID: "make-dir@1.3.0", Name: "make-dir", Version: "1.3.0", Locations: []types.Location{{StartLine: 9491, EndLine: 9496}}},
		{ID: "make-dir@2.1.0", Name: "make-dir", Version: "2.1.0", Locations: []types.Location{{StartLine: 9498, EndLine: 9504}}},
		{ID: "make-error@1.3.5", Name: "make-error", Version: "1.3.5", Locations: []types.Location{{StartLine: 9506, EndLine: 9509}}},
		{ID: "make-fetch-happen@4.0.1", Name: "make-fetch-happen", Version: "4.0.1", Locations: []types.Location{{StartLine: 9511, EndLine: 9526}}},
		{ID: "makeerror@1.0.11", Name: "makeerror", Version: "1.0.11", Locations: []types.Location{{StartLine: 9528, EndLine: 9533}}},
		{ID: "mamacro@0.0.3", Name: "mamacro", Version: "0.0.3", Locations: []types.Location{{StartLine: 9535, EndLine: 9538}}},
		{ID: "map-age-cleaner@0.1.3", Name: "map-age-cleaner", Version: "0.1.3", Locations: []types.Location{{StartLine: 9540, EndLine: 9545}}},
		{ID: "map-cache@0.2.2", Name: "map-cache", Version: "0.2.2", Locations: []types.Location{{StartLine: 9547, EndLine: 9550}}},
		{ID: "map-visit@1.0.0", Name: "map-visit", Version: "1.0.0", Locations: []types.Location{{StartLine: 9552, EndLine: 9557}}},
		{ID: "marked@0.3.19", Name: "marked", Version: "0.3.19", Locations: []types.Location{{StartLine: 9559, EndLine: 9562}}},
		{ID: "marksy@6.1.0", Name: "marksy", Version: "6.1.0", Locations: []types.Location{{StartLine: 9564, EndLine: 9571}}},
		{ID: "material-colors@1.2.6", Name: "material-colors", Version: "1.2.6", Locations: []types.Location{{StartLine: 9573, EndLine: 9576}}},
		{ID: "math-random@1.0.4", Name: "math-random", Version: "1.0.4", Locations: []types.Location{{StartLine: 9578, EndLine: 9581}}},
		{ID: "md5.js@1.3.5", Name: "md5.js", Version: "1.3.5", Locations: []types.Location{{StartLine: 9583, EndLine: 9590}}},
		{ID: "md5@2.2.1", Name: "md5", Version: "2.2.1", Locations: []types.Location{{StartLine: 9592, EndLine: 9599}}},
		{ID: "mdn-data@1.1.4", Name: "mdn-data", Version: "1.1.4", Locations: []types.Location{{StartLine: 9601, EndLine: 9604}}},
		{ID: "meant@1.0.1", Name: "meant", Version: "1.0.1", Locations: []types.Location{{StartLine: 9606, EndLine: 9609}}},
		{ID: "media-typer@0.3.0", Name: "media-typer", Version: "0.3.0", Locations: []types.Location{{StartLine: 9611, EndLine: 9614}}},
		{ID: "mem@1.1.0", Name: "mem", Version: "1.1.0", Locations: []types.Location{{StartLine: 9616, EndLine: 9621}}},
		{ID: "mem@4.3.0", Name: "mem", Version: "4.3.0", Locations: []types.Location{{StartLine: 9623, EndLine: 9630}}},
		{ID: "memoize-one@4.1.0", Name: "memoize-one", Version: "4.1.0", Locations: []types.Location{{StartLine: 9632, EndLine: 9635}}},
		{ID: "memory-fs@0.4.1", Name: "memory-fs", Version: "0.4.1", Locations: []types.Location{{StartLine: 9637, EndLine: 9643}}},
		{ID: "memorystream@0.3.1", Name: "memorystream", Version: "0.3.1", Locations: []types.Location{{StartLine: 9645, EndLine: 9648}}},
		{ID: "merge-deep@3.0.2", Name: "merge-deep", Version: "3.0.2", Locations: []types.Location{{StartLine: 9650, EndLine: 9657}}},
		{ID: "merge-descriptors@1.0.1", Name: "merge-descriptors", Version: "1.0.1", Locations: []types.Location{{StartLine: 9659, EndLine: 9662}}},
		{ID: "merge-dirs@0.2.1", Name: "merge-dirs", Version: "0.2.1", Locations: []types.Location{{StartLine: 9664, EndLine: 9672}}},
		{ID: "merge-stream@1.0.1", Name: "merge-stream", Version: "1.0.1", Locations: []types.Location{{StartLine: 9674, EndLine: 9679}}},
		{ID: "merge2@1.2.3", Name: "merge2", Version: "1.2.3", Locations: []types.Location{{StartLine: 9681, EndLine: 9684}}},
		{ID: "merge@1.2.1", Name: "merge", Version: "1.2.1", Locations: []types.Location{{StartLine: 9686, EndLine: 9689}}},
		{ID: "methods@1.1.2", Name: "methods", Version: "1.1.2", Locations: []types.Location{{StartLine: 9691, EndLine: 9694}}},
		{ID: "micromatch@2.3.11", Name: "micromatch", Version: "2.3.11", Locations: []types.Location{{StartLine: 9696, EndLine: 9713}}},
		{ID: "micromatch@3.1.10", Name: "micromatch", Version: "3.1.10", Locations: []types.Location{{StartLine: 9715, EndLine: 9732}}},
		{ID: "miller-rabin@4.0.1", Name: "miller-rabin", Version: "4.0.1", Locations: []types.Location{{StartLine: 9734, EndLine: 9740}}},
		{ID: "mime-db@1.40.0", Name: "mime-db", Version: "1.40.0", Locations: []types.Location{{StartLine: 9742, EndLine: 9745}}},
		{ID: "mime-types@2.1.24", Name: "mime-types", Version: "2.1.24", Locations: []types.Location{{StartLine: 9747, EndLine: 9752}}},
		{ID: "mime@1.4.1", Name: "mime", Version: "1.4.1", Locations: []types.Location{{StartLine: 9754, EndLine: 9757}}},
		{ID: "mime@2.4.2", Name: "mime", Version: "2.4.2", Locations: []types.Location{{StartLine: 9759, EndLine: 9762}}},
		{ID: "mimic-fn@1.2.0", Name: "mimic-fn", Version: "1.2.0", Locations: []types.Location{{StartLine: 9764, EndLine: 9767}}},
		{ID: "mimic-fn@2.1.0", Name: "mimic-fn", Version: "2.1.0", Locations: []types.Location{{StartLine: 9769, EndLine: 9772}}},
		{ID: "mimic-response@1.0.1", Name: "mimic-response", Version: "1.0.1", Locations: []types.Location{{StartLine: 9774, EndLine: 9777}}},
		{ID: "min-document@2.19.0", Name: "min-document", Version: "2.19.0", Locations: []types.Location{{StartLine: 9779, EndLine: 9784}}},
		{ID: "mini-css-extract-plugin@0.4.5", Name: "mini-css-extract-plugin", Version: "0.4.5", Locations: []types.Location{{StartLine: 9786, EndLine: 9793}}},
		{ID: "minimalistic-assert@1.0.1", Name: "minimalistic-assert", Version: "1.0.1", Locations: []types.Location{{StartLine: 9795, EndLine: 9798}}},
		{ID: "minimalistic-crypto-utils@1.0.1", Name: "minimalistic-crypto-utils", Version: "1.0.1", Locations: []types.Location{{StartLine: 9800, EndLine: 9803}}},
		{ID: "minimatch@3.0.4", Name: "minimatch", Version: "3.0.4", Locations: []types.Location{{StartLine: 9805, EndLine: 9810}}},
		{ID: "minimist@0.0.8", Name: "minimist", Version: "0.0.8", Locations: []types.Location{{StartLine: 9812, EndLine: 9815}}},
		{ID: "minimist@1.2.0", Name: "minimist", Version: "1.2.0", Locations: []types.Location{{StartLine: 9817, EndLine: 9820}}},
		{ID: "minimist@0.0.10", Name: "minimist", Version: "0.0.10", Locations: []types.Location{{StartLine: 9822, EndLine: 9825}}},
		{ID: "minipass@2.3.5", Name: "minipass", Version: "2.3.5", Locations: []types.Location{{StartLine: 9827, EndLine: 9833}}},
		{ID: "minizlib@1.2.1", Name: "minizlib", Version: "1.2.1", Locations: []types.Location{{StartLine: 9835, EndLine: 9840}}},
		{ID: "mississippi@2.0.0", Name: "mississippi", Version: "2.0.0", Locations: []types.Location{{StartLine: 9842, EndLine: 9856}}},
		{ID: "mississippi@3.0.0", Name: "mississippi", Version: "3.0.0", Locations: []types.Location{{StartLine: 9858, EndLine: 9872}}},
		{ID: "mixin-deep@1.3.1", Name: "mixin-deep", Version: "1.3.1", Locations: []types.Location{{StartLine: 9874, EndLine: 9880}}},
		{ID: "mixin-object@2.0.1", Name: "mixin-object", Version: "2.0.1", Locations: []types.Location{{StartLine: 9882, EndLine: 9888}}},
		{ID: "mkdirp@0.5.1", Name: "mkdirp", Version: "0.5.1", Locations: []types.Location{{StartLine: 9890, EndLine: 9895}}},
		{ID: "moment-timezone@0.5.23", Name: "moment-timezone", Version: "0.5.23", Locations: []types.Location{{StartLine: 9897, EndLine: 9902}}},
		{ID: "moment@2.23.0", Name: "moment", Version: "2.23.0", Locations: []types.Location{{StartLine: 9904, EndLine: 9907}}},
		{ID: "moment@2.24.0", Name: "moment", Version: "2.24.0", Locations: []types.Location{{StartLine: 9909, EndLine: 9912}}},
		{ID: "moo@0.4.3", Name: "moo", Version: "0.4.3", Locations: []types.Location{{StartLine: 9914, EndLine: 9917}}},
		{ID: "move-concurrently@1.0.1", Name: "move-concurrently", Version: "1.0.1", Locations: []types.Location{{StartLine: 9919, EndLine: 9929}}},
		{ID: "ms@2.0.0", Name: "ms", Version: "2.0.0", Locations: []types.Location{{StartLine: 9931, EndLine: 9934}}},
		{ID: "ms@2.1.1", Name: "ms", Version: "2.1.1", Locations: []types.Location{{StartLine: 9936, EndLine: 9939}}},
		{ID: "multicast-dns-service-types@1.1.0", Name: "multicast-dns-service-types", Version: "1.1.0", Locations: []types.Location{{StartLine: 9941, EndLine: 9944}}},
		{ID: "multicast-dns@6.2.3", Name: "multicast-dns", Version: "6.2.3", Locations: []types.Location{{StartLine: 9946, EndLine: 9952}}},
		{ID: "mute-stream@0.0.5", Name: "mute-stream", Version: "0.0.5", Locations: []types.Location{{StartLine: 9954, EndLine: 9957}}},
		{ID: "mute-stream@0.0.7", Name: "mute-stream", Version: "0.0.7", Locations: []types.Location{{StartLine: 9959, EndLine: 9962}}},
		{ID: "mute-stream@0.0.8", Name: "mute-stream", Version: "0.0.8", Locations: []types.Location{{StartLine: 9964, EndLine: 9967}}},
		{ID: "nan@2.13.2", Name: "nan", Version: "2.13.2", Locations: []types.Location{{StartLine: 9969, EndLine: 9972}}},
		{ID: "nanomatch@1.2.13", Name: "nanomatch", Version: "1.2.13", Locations: []types.Location{{StartLine: 9974, EndLine: 9989}}},
		{ID: "natural-compare@1.4.0", Name: "natural-compare", Version: "1.4.0", Locations: []types.Location{{StartLine: 9991, EndLine: 9994}}},
		{ID: "nearley@2.16.0", Name: "nearley", Version: "2.16.0", Locations: []types.Location{{StartLine: 9996, EndLine: 10005}}},
		{ID: "needle@2.4.0", Name: "needle", Version: "2.4.0", Locations: []types.Location{{StartLine: 10007, EndLine: 10014}}},
		{ID: "negotiator@0.6.2", Name: "negotiator", Version: "0.6.2", Locations: []types.Location{{StartLine: 10016, EndLine: 10019}}},
		{ID: "neo-async@2.6.1", Name: "neo-async", Version: "2.6.1", Locations: []types.Location{{StartLine: 10021, EndLine: 10024}}},
		{ID: "nested-object-assign@1.0.3", Name: "nested-object-assign", Version: "1.0.3", Locations: []types.Location{{StartLine: 10026, EndLine: 10029}}},
		{ID: "nice-try@1.0.5", Name: "nice-try", Version: "1.0.5", Locations: []types.Location{{StartLine: 10031, EndLine: 10034}}},
		{ID: "no-case@2.3.2", Name: "no-case", Version: "2.3.2", Locations: []types.Location{{StartLine: 10036, EndLine: 10041}}},
		{ID: "node-dir@0.1.8", Name: "node-dir", Version: "0.1.8", Locations: []types.Location{{StartLine: 10043, EndLine: 10046}}},
		{ID: "node-dir@0.1.17", Name: "node-dir", Version: "0.1.17", Locations: []types.Location{{StartLine: 10048, EndLine: 10053}}},
		{ID: "node-fetch-npm@2.0.2", Name: "node-fetch-npm", Version: "2.0.2", Locations: []types.Location{{StartLine: 10055, EndLine: 10062}}},
		{ID: "node-fetch@1.7.3", Name: "node-fetch", Version: "1.7.3", Locations: []types.Location{{StartLine: 10064, EndLine: 10070}}},
		{ID: "node-fetch@2.5.0", Name: "node-fetch", Version: "2.5.0", Locations: []types.Location{{StartLine: 10072, EndLine: 10075}}},
		{ID: "node-forge@0.7.5", Name: "node-forge", Version: "0.7.5", Locations: []types.Location{{StartLine: 10077, EndLine: 10080}}},
		{ID: "node-fs@0.1.7", Name: "node-fs", Version: "0.1.7", Locations: []types.Location{{StartLine: 10082, EndLine: 10085}}},
		{ID: "node-gyp@3.8.0", Name: "node-gyp", Version: "3.8.0", Locations: []types.Location{{StartLine: 10087, EndLine: 10103}}},
		{ID: "node-gyp@4.0.0", Name: "node-gyp", Version: "4.0.0", Locations: []types.Location{{StartLine: 10105, EndLine: 10120}}},
		{ID: "node-int64@0.4.0", Name: "node-int64", Version: "0.4.0", Locations: []types.Location{{StartLine: 10122, EndLine: 10125}}},
		{ID: "node-libs-browser@2.2.0", Name: "node-libs-browser", Version: "2.2.0", Locations: []types.Location{{StartLine: 10127, EndLine: 10154}}},
		{ID: "node-modules-regexp@1.0.0", Name: "node-modules-regexp", Version: "1.0.0", Locations: []types.Location{{StartLine: 10156, EndLine: 10159}}},
		{ID: "node-notifier@5.4.0", Name: "node-notifier", Version: "5.4.0", Locations: []types.Location{{StartLine: 10161, EndLine: 10170}}},
		{ID: "node-object-hash@1.4.2", Name: "node-object-hash", Version: "1.4.2", Locations: []types.Location{{StartLine: 10172, EndLine: 10175}}},
		{ID: "node-pre-gyp@0.12.0", Name: "node-pre-gyp", Version: "0.12.0", Locations: []types.Location{{StartLine: 10177, EndLine: 10191}}},
		{ID: "node-releases@1.1.19", Name: "node-releases", Version: "1.1.19", Locations: []types.Location{{StartLine: 10193, EndLine: 10198}}},
		{ID: "node-version@1.2.0", Name: "node-version", Version: "1.2.0", Locations: []types.Location{{StartLine: 10200, EndLine: 10203}}},
		{ID: "nomnom@1.8.1", Name: "nomnom", Version: "1.8.1", Locations: []types.Location{{StartLine: 10205, EndLine: 10211}}},
		{ID: "nopt@3.0.6", Name: "nopt", Version: "3.0.6", Locations: []types.Location{{StartLine: 10213, EndLine: 10218}}},
		{ID: "nopt@4.0.1", Name: "nopt", Version: "4.0.1", Locations: []types.Location{{StartLine: 10220, EndLine: 10226}}},
		{ID: "normalize-package-data@2.5.0", Name: "normalize-package-data", Version: "2.5.0", Locations: []types.Location{{StartLine: 10228, EndLine: 10236}}},
		{ID: "normalize-path@2.1.1", Name: "normalize-path", Version: "2.1.1", Locations: []types.Location{{StartLine: 10238, EndLine: 10243}}},
		{ID: "normalize-path@3.0.0", Name: "normalize-path", Version: "3.0.0", Locations: []types.Location{{StartLine: 10245, EndLine: 10248}}},
		{ID: "normalize-range@0.1.2", Name: "normalize-range", Version: "0.1.2", Locations: []types.Location{{StartLine: 10250, EndLine: 10253}}},
		{ID: "normalize-scroll-left@0.1.2", Name: "normalize-scroll-left", Version: "0.1.2", Locations: []types.Location{{StartLine: 10255, EndLine: 10258}}},
		{ID: "npm-audit-report@1.3.2", Name: "npm-audit-report", Version: "1.3.2", Locations: []types.Location{{StartLine: 10260, EndLine: 10266}}},
		{ID: "npm-bundled@1.0.6", Name: "npm-bundled", Version: "1.0.6", Locations: []types.Location{{StartLine: 10268, EndLine: 10271}}},
		{ID: "npm-cache-filename@1.0.2", Name: "npm-cache-filename", Version: "1.0.2", Locations: []types.Location{{StartLine: 10273, EndLine: 10276}}},
		{ID: "npm-install-checks@3.0.0", Name: "npm-install-checks", Version: "3.0.0", Locations: []types.Location{{StartLine: 10278, EndLine: 10283}}},
		{ID: "npm-lifecycle@2.1.1", Name: "npm-lifecycle", Version: "2.1.1", Locations: []types.Location{{StartLine: 10285, EndLine: 10297}}},
		{ID: "npm-logical-tree@1.2.1", Name: "npm-logical-tree", Version: "1.2.1", Locations: []types.Location{{StartLine: 10299, EndLine: 10302}}},
		{ID: "npm-package-arg@6.1.0", Name: "npm-package-arg", Version: "6.1.0", Locations: []types.Location{{StartLine: 10304, EndLine: 10312}}},
		{ID: "npm-packlist@1.4.1", Name: "npm-packlist", Version: "1.4.1", Locations: []types.Location{{StartLine: 10314, EndLine: 10320}}},
		{ID: "npm-path@2.0.4", Name: "npm-path", Version: "2.0.4", Locations: []types.Location{{StartLine: 10322, EndLine: 10327}}},
		{ID: "npm-pick-manifest@2.2.3", Name: "npm-pick-manifest", Version: "2.2.3", Locations: []types.Location{{StartLine: 10329, EndLine: 10336}}},
		{ID: "npm-profile@4.0.1", Name: "npm-profile", Version: "4.0.1", Locations: []types.Location{{StartLine: 10338, EndLine: 10345}}},
		{ID: "npm-registry-fetch@3.9.0", Name: "npm-registry-fetch", Version: "3.9.0", Locations: []types.Location{{StartLine: 10347, EndLine: 10357}}},
		{ID: "npm-run-all@4.1.5", Name: "npm-run-all", Version: "4.1.5", Locations: []types.Location{{StartLine: 10359, EndLine: 10372}}},
		{ID: "npm-run-path@2.0.2", Name: "npm-run-path", Version: "2.0.2", Locations: []types.Location{{StartLine: 10374, EndLine: 10379}}},
		{ID: "npm-user-validate@1.0.0", Name: "npm-user-validate", Version: "1.0.0", Locations: []types.Location{{StartLine: 10381, EndLine: 10384}}},
		{ID: "npm-which@3.0.1", Name: "npm-which", Version: "3.0.1", Locations: []types.Location{{StartLine: 10386, EndLine: 10393}}},
		{ID: "npm@6.9.0", Name: "npm", Version: "6.9.0", Locations: []types.Location{{StartLine: 10395, EndLine: 10507}}},
		{ID: "npmlog@4.1.2", Name: "npmlog", Version: "4.1.2", Locations: []types.Location{{StartLine: 10509, EndLine: 10517}}},
		{ID: "nth-check@1.0.2", Name: "nth-check", Version: "1.0.2", Locations: []types.Location{{StartLine: 10519, EndLine: 10524}}},
		{ID: "num2fraction@1.2.2", Name: "num2fraction", Version: "1.2.2", Locations: []types.Location{{StartLine: 10526, EndLine: 10529}}},
		{ID: "number-is-nan@1.0.1", Name: "number-is-nan", Version: "1.0.1", Locations: []types.Location{{StartLine: 10531, EndLine: 10534}}},
		{ID: "nwsapi@2.1.4", Name: "nwsapi", Version: "2.1.4", Locations: []types.Location{{StartLine: 10536, EndLine: 10539}}},
		{ID: "oauth-sign@0.9.0", Name: "oauth-sign", Version: "0.9.0", Locations: []types.Location{{StartLine: 10541, EndLine: 10544}}},
		{ID: "object-assign@4.1.1", Name: "object-assign", Version: "4.1.1", Locations: []types.Location{{StartLine: 10546, EndLine: 10549}}},
		{ID: "object-component@0.0.3", Name: "object-component", Version: "0.0.3", Locations: []types.Location{{StartLine: 10551, EndLine: 10554}}},
		{ID: "object-copy@0.1.0", Name: "object-copy", Version: "0.1.0", Locations: []types.Location{{StartLine: 10556, EndLine: 10563}}},
		{ID: "object-hash@1.3.1", Name: "object-hash", Version: "1.3.1", Locations: []types.Location{{StartLine: 10565, EndLine: 10568}}},
		{ID: "object-inspect@1.6.0", Name: "object-inspect", Version: "1.6.0", Locations: []types.Location{{StartLine: 10570, EndLine: 10573}}},
		{ID: "object-is@1.0.1", Name: "object-is", Version: "1.0.1", Locations: []types.Location{{StartLine: 10575, EndLine: 10578}}},
		{ID: "object-keys@1.1.1", Name: "object-keys", Version: "1.1.1", Locations: []types.Location{{StartLine: 10580, EndLine: 10583}}},
		{ID: "object-visit@1.0.1", Name: "object-visit", Version: "1.0.1", Locations: []types.Location{{StartLine: 10585, EndLine: 10590}}},
		{ID: "object.assign@4.1.0", Name: "object.assign", Version: "4.1.0", Locations: []types.Location{{StartLine: 10592, EndLine: 10600}}},
		{ID: "object.entries@1.1.0", Name: "object.entries", Version: "1.1.0", Locations: []types.Location{{StartLine: 10602, EndLine: 10610}}},
		{ID: "object.fromentries@2.0.0", Name: "object.fromentries", Version: "2.0.0", Locations: []types.Location{{StartLine: 10612, EndLine: 10620}}},
		{ID: "object.getownpropertydescriptors@2.0.3", Name: "object.getownpropertydescriptors", Version: "2.0.3", Locations: []types.Location{{StartLine: 10622, EndLine: 10628}}},
		{ID: "object.omit@2.0.1", Name: "object.omit", Version: "2.0.1", Locations: []types.Location{{StartLine: 10630, EndLine: 10636}}},
		{ID: "object.pick@1.3.0", Name: "object.pick", Version: "1.3.0", Locations: []types.Location{{StartLine: 10638, EndLine: 10643}}},
		{ID: "object.values@1.1.0", Name: "object.values", Version: "1.1.0", Locations: []types.Location{{StartLine: 10645, EndLine: 10653}}},
		{ID: "obuf@1.1.2", Name: "obuf", Version: "1.1.2", Locations: []types.Location{{StartLine: 10655, EndLine: 10658}}},
		{ID: "on-finished@2.3.0", Name: "on-finished", Version: "2.3.0", Locations: []types.Location{{StartLine: 10660, EndLine: 10665}}},
		{ID: "on-headers@1.0.2", Name: "on-headers", Version: "1.0.2", Locations: []types.Location{{StartLine: 10667, EndLine: 10670}}},
		{ID: "once@1.4.0", Name: "once", Version: "1.4.0", Locations: []types.Location{{StartLine: 10672, EndLine: 10677}}},
		{ID: "onetime@1.1.0", Name: "onetime", Version: "1.1.0", Locations: []types.Location{{StartLine: 10679, EndLine: 10682}}},
		{ID: "onetime@2.0.1", Name: "onetime", Version: "2.0.1", Locations: []types.Location{{StartLine: 10684, EndLine: 10689}}},
		{ID: "opener@1.5.1", Name: "opener", Version: "1.5.1", Locations: []types.Location{{StartLine: 10691, EndLine: 10694}}},
		{ID: "opn@5.4.0", Name: "opn", Version: "5.4.0", Locations: []types.Location{{StartLine: 10696, EndLine: 10701}}},
		{ID: "opn@5.5.0", Name: "opn", Version: "5.5.0", Locations: []types.Location{{StartLine: 10703, EndLine: 10708}}},
		{ID: "optimist@0.6.1", Name: "optimist", Version: "0.6.1", Locations: []types.Location{{StartLine: 10710, EndLine: 10716}}},
		{ID: "optionator@0.8.2", Name: "optionator", Version: "0.8.2", Locations: []types.Location{{StartLine: 10718, EndLine: 10728}}},
		{ID: "original@1.0.2", Name: "original", Version: "1.0.2", Locations: []types.Location{{StartLine: 10730, EndLine: 10735}}},
		{ID: "os-browserify@0.3.0", Name: "os-browserify", Version: "0.3.0", Locations: []types.Location{{StartLine: 10737, EndLine: 10740}}},
		{ID: "os-homedir@1.0.2", Name: "os-homedir", Version: "1.0.2", Locations: []types.Location{{StartLine: 10742, EndLine: 10745}}},
		{ID: "os-locale@1.4.0", Name: "os-locale", Version: "1.4.0", Locations: []types.Location{{StartLine: 10747, EndLine: 10752}}},
		{ID: "os-locale@2.1.0", Name: "os-locale", Version: "2.1.0", Locations: []types.Location{{StartLine: 10754, EndLine: 10761}}},
		{ID: "os-locale@3.1.0", Name: "os-locale", Version: "3.1.0", Locations: []types.Location{{StartLine: 10763, EndLine: 10770}}},
		{ID: "os-name@3.1.0", Name: "os-name", Version: "3.1.0", Locations: []types.Location{{StartLine: 10772, EndLine: 10778}}},
		{ID: "os-tmpdir@1.0.2", Name: "os-tmpdir", Version: "1.0.2", Locations: []types.Location{{StartLine: 10780, EndLine: 10783}}},
		{ID: "osenv@0.1.5", Name: "osenv", Version: "0.1.5", Locations: []types.Location{{StartLine: 10785, EndLine: 10791}}},
		{ID: "output-file-sync@1.1.2", Name: "output-file-sync", Version: "1.1.2", Locations: []types.Location{{StartLine: 10793, EndLine: 10800}}},
		{ID: "p-cancelable@0.3.0", Name: "p-cancelable", Version: "0.3.0", Locations: []types.Location{{StartLine: 10802, EndLine: 10805}}},
		{ID: "p-defer@1.0.0", Name: "p-defer", Version: "1.0.0", Locations: []types.Location{{StartLine: 10807, EndLine: 10810}}},
		{ID: "p-finally@1.0.0", Name: "p-finally", Version: "1.0.0", Locations: []types.Location{{StartLine: 10812, EndLine: 10815}}},
		{ID: "p-is-promise@2.1.0", Name: "p-is-promise", Version: "2.1.0", Locations: []types.Location{{StartLine: 10817, EndLine: 10820}}},
		{ID: "p-limit@1.3.0", Name: "p-limit", Version: "1.3.0", Locations: []types.Location{{StartLine: 10822, EndLine: 10827}}},
		{ID: "p-limit@2.2.0", Name: "p-limit", Version: "2.2.0", Locations: []types.Location{{StartLine: 10829, EndLine: 10834}}},
		{ID: "p-locate@2.0.0", Name: "p-locate", Version: "2.0.0", Locations: []types.Location{{StartLine: 10836, EndLine: 10841}}},
		{ID: "p-locate@3.0.0", Name: "p-locate", Version: "3.0.0", Locations: []types.Location{{StartLine: 10843, EndLine: 10848}}},
		{ID: "p-map@1.2.0", Name: "p-map", Version: "1.2.0", Locations: []types.Location{{StartLine: 10850, EndLine: 10853}}},
		{ID: "p-map@2.1.0", Name: "p-map", Version: "2.1.0", Locations: []types.Location{{StartLine: 10855, EndLine: 10858}}},
		{ID: "p-timeout@1.2.1", Name: "p-timeout", Version: "1.2.1", Locations: []types.Location{{StartLine: 10860, EndLine: 10865}}},
		{ID: "p-try@1.0.0", Name: "p-try", Version: "1.0.0", Locations: []types.Location{{StartLine: 10867, EndLine: 10870}}},
		{ID: "p-try@2.2.0", Name: "p-try", Version: "2.2.0", Locations: []types.Location{{StartLine: 10872, EndLine: 10875}}},
		{ID: "package-json@4.0.1", Name: "package-json", Version: "4.0.1", Locations: []types.Location{{StartLine: 10877, EndLine: 10885}}},
		{ID: "pacote@9.5.0", Name: "pacote", Version: "9.5.0", Locations: []types.Location{{StartLine: 10887, EndLine: 10918}}},
		{ID: "pako@1.0.10", Name: "pako", Version: "1.0.10", Locations: []types.Location{{StartLine: 10920, EndLine: 10923}}},
		{ID: "parallel-transform@1.1.0", Name: "parallel-transform", Version: "1.1.0", Locations: []types.Location{{StartLine: 10925, EndLine: 10932}}},
		{ID: "param-case@2.1.1", Name: "param-case", Version: "2.1.1", Locations: []types.Location{{StartLine: 10934, EndLine: 10939}}},
		{ID: "parent-module@1.0.1", Name: "parent-module", Version: "1.0.1", Locations: []types.Location{{StartLine: 10941, EndLine: 10946}}},
		{ID: "parse-asn1@5.1.4", Name: "parse-asn1", Version: "5.1.4", Locations: []types.Location{{StartLine: 10948, EndLine: 10958}}},
		{ID: "parse-glob@3.0.4", Name: "parse-glob", Version: "3.0.4", Locations: []types.Location{{StartLine: 10960, EndLine: 10968}}},
		{ID: "parse-json@2.2.0", Name: "parse-json", Version: "2.2.0", Locations: []types.Location{{StartLine: 10970, EndLine: 10975}}},
		{ID: "parse-json@4.0.0", Name: "parse-json", Version: "4.0.0", Locations: []types.Location{{StartLine: 10977, EndLine: 10983}}},
		{ID: "parse-passwd@1.0.0", Name: "parse-passwd", Version: "1.0.0", Locations: []types.Location{{StartLine: 10985, EndLine: 10988}}},
		{ID: "parse5@4.0.0", Name: "parse5", Version: "4.0.0", Locations: []types.Location{{StartLine: 10990, EndLine: 10993}}},
		{ID: "parse5@3.0.3", Name: "parse5", Version: "3.0.3", Locations: []types.Location{{StartLine: 10995, EndLine: 11000}}},
		{ID: "parse5@5.1.0", Name: "parse5", Version: "5.1.0", Locations: []types.Location{{StartLine: 11002, EndLine: 11005}}},
		{ID: "parseqs@0.0.5", Name: "parseqs", Version: "0.0.5", Locations: []types.Location{{StartLine: 11007, EndLine: 11012}}},
		{ID: "parseuri@0.0.5", Name: "parseuri", Version: "0.0.5", Locations: []types.Location{{StartLine: 11014, EndLine: 11019}}},
		{ID: "parseurl@1.3.3", Name: "parseurl", Version: "1.3.3", Locations: []types.Location{{StartLine: 11021, EndLine: 11024}}},
		{ID: "pascalcase@0.1.1", Name: "pascalcase", Version: "0.1.1", Locations: []types.Location{{StartLine: 11026, EndLine: 11029}}},
		{ID: "path-browserify@0.0.0", Name: "path-browserify", Version: "0.0.0", Locations: []types.Location{{StartLine: 11031, EndLine: 11034}}},
		{ID: "path-dirname@1.0.2", Name: "path-dirname", Version: "1.0.2", Locations: []types.Location{{StartLine: 11036, EndLine: 11039}}},
		{ID: "path-exists@2.1.0", Name: "path-exists", Version: "2.1.0", Locations: []types.Location{{StartLine: 11041, EndLine: 11046}}},
		{ID: "path-exists@3.0.0", Name: "path-exists", Version: "3.0.0", Locations: []types.Location{{StartLine: 11048, EndLine: 11051}}},
		{ID: "path-is-absolute@1.0.1", Name: "path-is-absolute", Version: "1.0.1", Locations: []types.Location{{StartLine: 11053, EndLine: 11056}}},
		{ID: "path-is-inside@1.0.2", Name: "path-is-inside", Version: "1.0.2", Locations: []types.Location{{StartLine: 11058, EndLine: 11061}}},
		{ID: "path-key@2.0.1", Name: "path-key", Version: "2.0.1", Locations: []types.Location{{StartLine: 11063, EndLine: 11066}}},
		{ID: "path-parse@1.0.6", Name: "path-parse", Version: "1.0.6", Locations: []types.Location{{StartLine: 11068, EndLine: 11071}}},
		{ID: "path-to-regexp@0.1.7", Name: "path-to-regexp", Version: "0.1.7", Locations: []types.Location{{StartLine: 11073, EndLine: 11076}}},
		{ID: "path-to-regexp@1.7.0", Name: "path-to-regexp", Version: "1.7.0", Locations: []types.Location{{StartLine: 11078, EndLine: 11083}}},
		{ID: "path-type@1.1.0", Name: "path-type", Version: "1.1.0", Locations: []types.Location{{StartLine: 11085, EndLine: 11092}}},
		{ID: "path-type@2.0.0", Name: "path-type", Version: "2.0.0", Locations: []types.Location{{StartLine: 11094, EndLine: 11099}}},
		{ID: "path-type@3.0.0", Name: "path-type", Version: "3.0.0", Locations: []types.Location{{StartLine: 11101, EndLine: 11106}}},
		{ID: "path@0.12.7", Name: "path", Version: "0.12.7", Locations: []types.Location{{StartLine: 11108, EndLine: 11114}}},
		{ID: "pbkdf2@3.0.17", Name: "pbkdf2", Version: "3.0.17", Locations: []types.Location{{StartLine: 11116, EndLine: 11125}}},
		{ID: "performance-now@2.1.0", Name: "performance-now", Version: "2.1.0", Locations: []types.Location{{StartLine: 11127, EndLine: 11130}}},
		{ID: "pidtree@0.3.0", Name: "pidtree", Version: "0.3.0", Locations: []types.Location{{StartLine: 11132, EndLine: 11135}}},
		{ID: "pify@2.3.0", Name: "pify", Version: "2.3.0", Locations: []types.Location{{StartLine: 11137, EndLine: 11140}}},
		{ID: "pify@3.0.0", Name: "pify", Version: "3.0.0", Locations: []types.Location{{StartLine: 11142, EndLine: 11145}}},
		{ID: "pify@4.0.1", Name: "pify", Version: "4.0.1", Locations: []types.Location{{StartLine: 11147, EndLine: 11150}}},
		{ID: "pinkie-promise@2.0.1", Name: "pinkie-promise", Version: "2.0.1", Locations: []types.Location{{StartLine: 11152, EndLine: 11157}}},
		{ID: "pinkie@2.0.4", Name: "pinkie", Version: "2.0.4", Locations: []types.Location{{StartLine: 11159, EndLine: 11162}}},
		{ID: "pirates@4.0.1", Name: "pirates", Version: "4.0.1", Locations: []types.Location{{StartLine: 11164, EndLine: 11169}}},
		{ID: "pkg-dir@1.0.0", Name: "pkg-dir", Version: "1.0.0", Locations: []types.Location{{StartLine: 11171, EndLine: 11176}}},
		{ID: "pkg-dir@2.0.0", Name: "pkg-dir", Version: "2.0.0", Locations: []types.Location{{StartLine: 11178, EndLine: 11183}}},
		{ID: "pkg-dir@3.0.0", Name: "pkg-dir", Version: "3.0.0", Locations: []types.Location{{StartLine: 11185, EndLine: 11190}}},
		{ID: "pkg-up@2.0.0", Name: "pkg-up", Version: "2.0.0", Locations: []types.Location{{StartLine: 11192, EndLine: 11197}}},
		{ID: "please-upgrade-node@3.1.1", Name: "please-upgrade-node", Version: "3.1.1", Locations: []types.Location{{StartLine: 11199, EndLine: 11204}}},
		{ID: "pn@1.1.0", Name: "pn", Version: "1.1.0", Locations: []types.Location{{StartLine: 11206, EndLine: 11209}}},
		{ID: "popper.js@1.15.0", Name: "popper.js", Version: "1.15.0", Locations: []types.Location{{StartLine: 11211, EndLine: 11214}}},
		{ID: "portfinder@1.0.20", Name: "portfinder", Version: "1.0.20", Locations: []types.Location{{StartLine: 11216, EndLine: 11223}}},
		{ID: "posix-character-classes@0.1.1", Name: "posix-character-classes", Version: "0.1.1", Locations: []types.Location{{StartLine: 11225, EndLine: 11228}}},
		{ID: "postcss-flexbugs-fixes@4.1.0", Name: "postcss-flexbugs-fixes", Version: "4.1.0", Locations: []types.Location{{StartLine: 11230, EndLine: 11235}}},
		{ID: "postcss-load-config@2.0.0", Name: "postcss-load-config", Version: "2.0.0", Locations: []types.Location{{StartLine: 11237, EndLine: 11243}}},
		{ID: "postcss-loader@3.0.0", Name: "postcss-loader", Version: "3.0.0", Locations: []types.Location{{StartLine: 11245, EndLine: 11253}}},
		{ID: "postcss-modules-extract-imports@1.2.1", Name: "postcss-modules-extract-imports", Version: "1.2.1", Locations: []types.Location{{StartLine: 11255, EndLine: 11260}}},
		{ID: "postcss-modules-local-by-default@1.2.0", Name: "postcss-modules-local-by-default", Version: "1.2.0", Locations: []types.Location{{StartLine: 11262, EndLine: 11268}}},
		{ID: "postcss-modules-scope@1.1.0", Name: "postcss-modules-scope", Version: "1.1.0", Locations: []types.Location{{StartLine: 11270, EndLine: 11276}}},
		{ID: "postcss-modules-values@1.3.0", Name: "postcss-modules-values", Version: "1.3.0", Locations: []types.Location{{StartLine: 11278, EndLine: 11284}}},
		{ID: "postcss-value-parser@3.3.1", Name: "postcss-value-parser", Version: "3.3.1", Locations: []types.Location{{StartLine: 11286, EndLine: 11289}}},
		{ID: "postcss@6.0.23", Name: "postcss", Version: "6.0.23", Locations: []types.Location{{StartLine: 11291, EndLine: 11298}}},
		{ID: "postcss@7.0.16", Name: "postcss", Version: "7.0.16", Locations: []types.Location{{StartLine: 11300, EndLine: 11307}}},
		{ID: "prelude-ls@1.1.2", Name: "prelude-ls", Version: "1.1.2", Locations: []types.Location{{StartLine: 11309, EndLine: 11312}}},
		{ID: "prepend-http@1.0.4", Name: "prepend-http", Version: "1.0.4", Locations: []types.Location{{StartLine: 11314, EndLine: 11317}}},
		{ID: "preserve@0.2.0", Name: "preserve", Version: "0.2.0", Locations: []types.Location{{StartLine: 11319, EndLine: 11322}}},
		{ID: "pretty-error@2.1.1", Name: "pretty-error", Version: "2.1.1", Locations: []types.Location{{StartLine: 11324, EndLine: 11330}}},
		{ID: "pretty-format@23.6.0", Name: "pretty-format", Version: "23.6.0", Locations: []types.Location{{StartLine: 11332, EndLine: 11338}}},
		{ID: "pretty-hrtime@1.0.3", Name: "pretty-hrtime", Version: "1.0.3", Locations: []types.Location{{StartLine: 11340, EndLine: 11343}}},
		{ID: "private@0.1.8", Name: "private", Version: "0.1.8", Locations: []types.Location{{StartLine: 11345, EndLine: 11348}}},
		{ID: "process-nextick-args@1.0.7", Name: "process-nextick-args", Version: "1.0.7", Locations: []types.Location{{StartLine: 11350, EndLine: 11353}}},
		{ID: "process-nextick-args@2.0.0", Name: "process-nextick-args", Version: "2.0.0", Locations: []types.Location{{StartLine: 11355, EndLine: 11358}}},
		{ID: "process@0.11.10", Name: "process", Version: "0.11.10", Locations: []types.Location{{StartLine: 11360, EndLine: 11363}}},
		{ID: "process@0.5.2", Name: "process", Version: "0.5.2", Locations: []types.Location{{StartLine: 11365, EndLine: 11368}}},
		{ID: "progress@2.0.3", Name: "progress", Version: "2.0.3", Locations: []types.Location{{StartLine: 11370, EndLine: 11373}}},
		{ID: "promise-inflight@1.0.1", Name: "promise-inflight", Version: "1.0.1", Locations: []types.Location{{StartLine: 11375, EndLine: 11378}}},
		{ID: "promise-polyfill@6.1.0", Name: "promise-polyfill", Version: "6.1.0", Locations: []types.Location{{StartLine: 11380, EndLine: 11383}}},
		{ID: "promise-retry@1.1.1", Name: "promise-retry", Version: "1.1.1", Locations: []types.Location{{StartLine: 11385, EndLine: 11391}}},
		{ID: "promise.allsettled@1.0.1", Name: "promise.allsettled", Version: "1.0.1", Locations: []types.Location{{StartLine: 11393, EndLine: 11400}}},
		{ID: "promise.prototype.finally@3.1.0", Name: "promise.prototype.finally", Version: "3.1.0", Locations: []types.Location{{StartLine: 11402, EndLine: 11409}}},
		{ID: "promise@7.3.1", Name: "promise", Version: "7.3.1", Locations: []types.Location{{StartLine: 11411, EndLine: 11416}}},
		{ID: "prompts@0.1.14", Name: "prompts", Version: "0.1.14", Locations: []types.Location{{StartLine: 11418, EndLine: 11424}}},
		{ID: "promzard@0.3.0", Name: "promzard", Version: "0.3.0", Locations: []types.Location{{StartLine: 11426, EndLine: 11431}}},
		{ID: "prop-types-exact@1.2.0", Name: "prop-types-exact", Version: "1.2.0", Locations: []types.Location{{StartLine: 11433, EndLine: 11440}}},
		{ID: "prop-types@15.7.2", Name: "prop-types", Version: "15.7.2", Locations: []types.Location{{StartLine: 11442, EndLine: 11449}}},
		{ID: "property-information@5.1.0", Name: "property-information", Version: "5.1.0", Locations: []types.Location{{StartLine: 11451, EndLine: 11456}}},
		{ID: "proto-list@1.2.4", Name: "proto-list", Version: "1.2.4", Locations: []types.Location{{StartLine: 11458, EndLine: 11461}}},
		{ID: "protoduck@5.0.1", Name: "protoduck", Version: "5.0.1", Locations: []types.Location{{StartLine: 11463, EndLine: 11468}}},
		{ID: "proxy-addr@2.0.5", Name: "proxy-addr", Version: "2.0.5", Locations: []types.Location{{StartLine: 11470, EndLine: 11476}}},
		{ID: "prr@1.0.1", Name: "prr", Version: "1.0.1", Locations: []types.Location{{StartLine: 11478, EndLine: 11481}}},
		{ID: "pseudomap@1.0.2", Name: "pseudomap", Version: "1.0.2", Locations: []types.Location{{StartLine: 11483, EndLine: 11486}}},
		{ID: "psl@1.1.31", Name: "psl", Version: "1.1.31", Locations: []types.Location{{StartLine: 11488, EndLine: 11491}}},
		{ID: "public-encrypt@4.0.3", Name: "public-encrypt", Version: "4.0.3", Locations: []types.Location{{StartLine: 11493, EndLine: 11503}}},
		{ID: "pump@2.0.1", Name: "pump", Version: "2.0.1", Locations: []types.Location{{StartLine: 11505, EndLine: 11511}}},
		{ID: "pump@3.0.0", Name: "pump", Version: "3.0.0", Locations: []types.Location{{StartLine: 11513, EndLine: 11519}}},
		{ID: "pumpify@1.5.1", Name: "pumpify", Version: "1.5.1", Locations: []types.Location{{StartLine: 11521, EndLine: 11528}}},
		{ID: "punycode@1.3.2", Name: "punycode", Version: "1.3.2", Locations: []types.Location{{StartLine: 11530, EndLine: 11533}}},
		{ID: "punycode@1.4.1", Name: "punycode", Version: "1.4.1", Locations: []types.Location{{StartLine: 11535, EndLine: 11538}}},
		{ID: "punycode@2.1.1", Name: "punycode", Version: "2.1.1", Locations: []types.Location{{StartLine: 11540, EndLine: 11543}}},
		{ID: "q@1.5.1", Name: "q", Version: "1.5.1", Locations: []types.Location{{StartLine: 11545, EndLine: 11548}}},
		{ID: "qrcode-terminal@0.12.0", Name: "qrcode-terminal", Version: "0.12.0", Locations: []types.Location{{StartLine: 11550, EndLine: 11553}}},
		{ID: "qs@6.5.2", Name: "qs", Version: "6.5.2", Locations: []types.Location{{StartLine: 11555, EndLine: 11558}}},
		{ID: "qs@6.7.0", Name: "qs", Version: "6.7.0", Locations: []types.Location{{StartLine: 11560, EndLine: 11563}}},
		{ID: "query-string@6.5.0", Name: "query-string", Version: "6.5.0", Locations: []types.Location{{StartLine: 11565, EndLine: 11572}}},
		{ID: "querystring-es3@0.2.1", Name: "querystring-es3", Version: "0.2.1", Locations: []types.Location{{StartLine: 11574, EndLine: 11577}}},
		{ID: "querystring@0.2.0", Name: "querystring", Version: "0.2.0", Locations: []types.Location{{StartLine: 11579, EndLine: 11582}}},
		{ID: "querystringify@2.1.1", Name: "querystringify", Version: "2.1.1", Locations: []types.Location{{StartLine: 11584, EndLine: 11587}}},
		{ID: "qw@1.0.1", Name: "qw", Version: "1.0.1", Locations: []types.Location{{StartLine: 11589, EndLine: 11592}}},
		{ID: "raf@3.4.1", Name: "raf", Version: "3.4.1", Locations: []types.Location{{StartLine: 11594, EndLine: 11599}}},
		{ID: "railroad-diagrams@1.0.0", Name: "railroad-diagrams", Version: "1.0.0", Locations: []types.Location{{StartLine: 11601, EndLine: 11604}}},
		{ID: "ramda@0.21.0", Name: "ramda", Version: "0.21.0", Locations: []types.Location{{StartLine: 11606, EndLine: 11609}}},
		{ID: "randexp@0.4.6", Name: "randexp", Version: "0.4.6", Locations: []types.Location{{StartLine: 11611, EndLine: 11617}}},
		{ID: "randomatic@3.1.1", Name: "randomatic", Version: "3.1.1", Locations: []types.Location{{StartLine: 11619, EndLine: 11626}}},
		{ID: "randombytes@2.1.0", Name: "randombytes", Version: "2.1.0", Locations: []types.Location{{StartLine: 11628, EndLine: 11633}}},
		{ID: "randomfill@1.0.4", Name: "randomfill", Version: "1.0.4", Locations: []types.Location{{StartLine: 11635, EndLine: 11641}}},
		{ID: "range-parser@1.2.1", Name: "range-parser", Version: "1.2.1", Locations: []types.Location{{StartLine: 11643, EndLine: 11646}}},
		{ID: "raven-for-redux@1.4.0", Name: "raven-for-redux", Version: "1.4.0", Locations: []types.Location{{StartLine: 11648, EndLine: 11651}}},
		{ID: "raven-js@3.27.0", Name: "raven-js", Version: "3.27.0", Locations: []types.Location{{StartLine: 11653, EndLine: 11656}}},
		{ID: "raw-body@2.3.3", Name: "raw-body", Version: "2.3.3", Locations: []types.Location{{StartLine: 11658, EndLine: 11666}}},
		{ID: "raw-loader@0.5.1", Name: "raw-loader", Version: "0.5.1", Locations: []types.Location{{StartLine: 11668, EndLine: 11671}}},
		{ID: "rc@1.2.8", Name: "rc", Version: "1.2.8", Locations: []types.Location{{StartLine: 11673, EndLine: 11681}}},
		{ID: "react-addons-create-fragment@15.6.2", Name: "react-addons-create-fragment", Version: "15.6.2", Locations: []types.Location{{StartLine: 11683, EndLine: 11690}}},
		{ID: "react-color@2.17.3", Name: "react-color", Version: "2.17.3", Locations: []types.Location{{StartLine: 11692, EndLine: 11702}}},
		{ID: "react-datepicker@2.5.0", Name: "react-datepicker", Version: "2.5.0", Locations: []types.Location{{StartLine: 11704, EndLine: 11713}}},
		{ID: "react-dev-utils@6.1.1", Name: "react-dev-utils", Version: "6.1.1", Locations: []types.Location{{StartLine: 11715, EndLine: 11743}}},
		{ID: "react-docgen@3.0.0", Name: "react-docgen", Version: "3.0.0", Locations: []types.Location{{StartLine: 11745, EndLine: 11756}}},
		{ID: "react-dom@16.8.3", Name: "react-dom", Version: "16.8.3", Locations: []types.Location{{StartLine: 11758, EndLine: 11766}}},
		{ID: "react-dom@16.8.6", Name: "react-dom", Version: "16.8.6", Locations: []types.Location{{StartLine: 11768, EndLine: 11776}}},
		{ID: "react-dropzone@10.1.4", Name: "react-dropzone", Version: "10.1.4", Locations: []types.Location{{StartLine: 11778, EndLine: 11785}}},
		{ID: "react-error-overlay@5.1.6", Name: "react-error-overlay", Version: "5.1.6", Locations: []types.Location{{StartLine: 11787, EndLine: 11790}}},
		{ID: "react-event-listener@0.6.6", Name: "react-event-listener", Version: "0.6.6", Locations: []types.Location{{StartLine: 11792, EndLine: 11799}}},
		{ID: "react-fast-compare@2.0.4", Name: "react-fast-compare", Version: "2.0.4", Locations: []types.Location{{StartLine: 11801, EndLine: 11804}}},
		{ID: "react-fuzzy@0.5.2", Name: "react-fuzzy", Version: "0.5.2", Locations: []types.Location{{StartLine: 11806, EndLine: 11814}}},
		{ID: "react-ga@2.5.7", Name: "react-ga", Version: "2.5.7", Locations: []types.Location{{StartLine: 11816, EndLine: 11819}}},
		{ID: "react-gateway@3.0.0", Name: "react-gateway", Version: "3.0.0", Locations: []types.Location{{StartLine: 11821, EndLine: 11827}}},
		{ID: "react-inspector@2.3.1", Name: "react-inspector", Version: "2.3.1", Locations: []types.Location{{StartLine: 11829, EndLine: 11836}}},
		{ID: "react-intl-universal@1.16.2", Name: "react-intl-universal", Version: "1.16.2", Locations: []types.Location{{StartLine: 11838, EndLine: 11853}}},
		{ID: "react-is@16.8.6", Name: "react-is", Version: "16.8.6", Locations: []types.Location{{StartLine: 11855, EndLine: 11858}}},
		{ID: "react-lifecycles-compat@3.0.4", Name: "react-lifecycles-compat", Version: "3.0.4", Locations: []types.Location{{StartLine: 11860, EndLine: 11863}}},
		{ID: "react-modal@3.8.1", Name: "react-modal", Version: "3.8.1", Locations: []types.Location{{StartLine: 11865, EndLine: 11873}}},
		{ID: "react-onclickoutside@6.8.0", Name: "react-onclickoutside", Version: "6.8.0", Locations: []types.Location{{StartLine: 11875, EndLine: 11878}}},
		{ID: "react-popper@1.3.3", Name: "react-popper", Version: "1.3.3", Locations: []types.Location{{StartLine: 11880, EndLine: 11890}}},
		{ID: "react-prop-types@0.4.0", Name: "react-prop-types", Version: "0.4.0", Locations: []types.Location{{StartLine: 11892, EndLine: 11897}}},
		{ID: "react-redux@6.0.1", Name: "react-redux", Version: "6.0.1", Locations: []types.Location{{StartLine: 11899, EndLine: 11909}}},
		{ID: "react-router-dom@4.3.1", Name: "react-router-dom", Version: "4.3.1", Locations: []types.Location{{StartLine: 11911, EndLine: 11921}}},
		{ID: "react-router@4.3.1", Name: "react-router", Version: "4.3.1", Locations: []types.Location{{StartLine: 11923, EndLine: 11934}}},
		{ID: "react-split-pane@0.1.87", Name: "react-split-pane", Version: "0.1.87", Locations: []types.Location{{StartLine: 11936, EndLine: 11943}}},
		{ID: "react-style-proptype@3.2.2", Name: "react-style-proptype", Version: "3.2.2", Locations: []types.Location{{StartLine: 11945, EndLine: 11950}}},
		{ID: "react-test-renderer@16.8.6", Name: "react-test-renderer", Version: "16.8.6", Locations: []types.Location{{StartLine: 11952, EndLine: 11960}}},
		{ID: "react-textarea-autosize@7.1.0", Name: "react-textarea-autosize", Version: "7.1.0", Locations: []types.Location{{StartLine: 11962, EndLine: 11968}}},
		{ID: "react-transition-group@2.9.0", Name: "react-transition-group", Version: "2.9.0", Locations: []types.Location{{StartLine: 11970, EndLine: 11978}}},
		{ID: "react-treebeard@3.1.0", Name: "react-treebeard", Version: "3.1.0", Locations: []types.Location{{StartLine: 11980, EndLine: 11991}}},
		{ID: "react-virtualized@9.21.1", Name: "react-virtualized", Version: "9.21.1", Locations: []types.Location{{StartLine: 11993, EndLine: 12004}}},
		{ID: "react@16.8.3", Name: "react", Version: "16.8.3", Locations: []types.Location{{StartLine: 12006, EndLine: 12014}}},
		{ID: "react@16.8.6", Name: "react", Version: "16.8.6", Locations: []types.Location{{StartLine: 12016, EndLine: 12024}}},
		{ID: "reactcss@1.2.3", Name: "reactcss", Version: "1.2.3", Locations: []types.Location{{StartLine: 12026, EndLine: 12031}}},
		{ID: "read-cmd-shim@1.0.1", Name: "read-cmd-shim", Version: "1.0.1", Locations: []types.Location{{StartLine: 12033, EndLine: 12038}}},
		{ID: "read-installed@4.0.3", Name: "read-installed", Version: "4.0.3", Locations: []types.Location{{StartLine: 12040, EndLine: 12052}}},
		{ID: "read-package-json@2.0.13", Name: "read-package-json", Version: "2.0.13", Locations: []types.Location{{StartLine: 12054, EndLine: 12064}}},
		{ID: "read-package-tree@5.2.2", Name: "read-package-tree", Version: "5.2.2", Locations: []types.Location{{StartLine: 12066, EndLine: 12075}}},
		{ID: "read-pkg-up@1.0.1", Name: "read-pkg-up", Version: "1.0.1", Locations: []types.Location{{StartLine: 12077, EndLine: 12083}}},
		{ID: "read-pkg-up@2.0.0", Name: "read-pkg-up", Version: "2.0.0", Locations: []types.Location{{StartLine: 12085, EndLine: 12091}}},
		{ID: "read-pkg@1.1.0", Name: "read-pkg", Version: "1.1.0", Locations: []types.Location{{StartLine: 12093, EndLine: 12100}}},
		{ID: "read-pkg@2.0.0", Name: "read-pkg", Version: "2.0.0", Locations: []types.Location{{StartLine: 12102, EndLine: 12109}}},
		{ID: "read-pkg@3.0.0", Name: "read-pkg", Version: "3.0.0", Locations: []types.Location{{StartLine: 12111, EndLine: 12118}}},
		{ID: "read-pkg@4.0.1", Name: "read-pkg", Version: "4.0.1", Locations: []types.Location{{StartLine: 12120, EndLine: 12127}}},
		{ID: "read@1.0.7", Name: "read", Version: "1.0.7", Locations: []types.Location{{StartLine: 12129, EndLine: 12134}}},
		{ID: "readable-stream@2.3.6", Name: "readable-stream", Version: "2.3.6", Locations: []types.Location{{StartLine: 12136, EndLine: 12147}}},
		{ID: "readable-stream@3.3.0", Name: "readable-stream", Version: "3.3.0", Locations: []types.Location{{StartLine: 12149, EndLine: 12156}}},
		{ID: "readable-stream@1.1.14", Name: "readable-stream", Version: "1.1.14", Locations: []types.Location{{StartLine: 12158, EndLine: 12166}}},
		{ID: "readable-stream@2.1.5", Name: "readable-stream", Version: "2.1.5", Locations: []types.Location{{StartLine: 12168, EndLine: 12179}}},
		{ID: "readdir-scoped-modules@1.0.2", Name: "readdir-scoped-modules", Version: "1.0.2", Locations: []types.Location{{StartLine: 12181, EndLine: 12189}}},
		{ID: "readdirp@2.2.1", Name: "readdirp", Version: "2.2.1", Locations: []types.Location{{StartLine: 12191, EndLine: 12198}}},
		{ID: "readline2@1.0.1", Name: "readline2", Version: "1.0.1", Locations: []types.Location{{StartLine: 12200, EndLine: 12207}}},
		{ID: "realpath-native@1.1.0", Name: "realpath-native", Version: "1.1.0", Locations: []types.Location{{StartLine: 12209, EndLine: 12214}}},
		{ID: "recast@0.14.7", Name: "recast", Version: "0.14.7", Locations: []types.Location{{StartLine: 12216, EndLine: 12224}}},
		{ID: "recast@0.15.5", Name: "recast", Version: "0.15.5", Locations: []types.Location{{StartLine: 12226, EndLine: 12234}}},
		{ID: "recast@0.16.2", Name: "recast", Version: "0.16.2", Locations: []types.Location{{StartLine: 12236, EndLine: 12244}}},
		{ID: "rechoir@0.6.2", Name: "rechoir", Version: "0.6.2", Locations: []types.Location{{StartLine: 12246, EndLine: 12251}}},
		{ID: "recompose@0.30.0", Name: "recompose", Version: "0.30.0", Locations: []types.Location{{StartLine: 12253, EndLine: 12263}}},
		{ID: "recursive-readdir@2.2.2", Name: "recursive-readdir", Version: "2.2.2", Locations: []types.Location{{StartLine: 12265, EndLine: 12270}}},
		{ID: "redux-thunk@2.3.0", Name: "redux-thunk", Version: "2.3.0", Locations: []types.Location{{StartLine: 12272, EndLine: 12275}}},
		{ID: "redux@4.0.1", Name: "redux", Version: "4.0.1", Locations: []types.Location{{StartLine: 12277, EndLine: 12283}}},
		{ID: "reflect.ownkeys@0.2.0", Name: "reflect.ownkeys", Version: "0.2.0", Locations: []types.Location{{StartLine: 12285, EndLine: 12288}}},
		{ID: "regenerate-unicode-properties@8.1.0", Name: "regenerate-unicode-properties", Version: "8.1.0", Locations: []types.Location{{StartLine: 12290, EndLine: 12295}}},
		{ID: "regenerate@1.4.0", Name: "regenerate", Version: "1.4.0", Locations: []types.Location{{StartLine: 12297, EndLine: 12300}}},
		{ID: "regenerator-runtime@0.10.5", Name: "regenerator-runtime", Version: "0.10.5", Locations: []types.Location{{StartLine: 12302, EndLine: 12305}}},
		{ID: "regenerator-runtime@0.11.1", Name: "regenerator-runtime", Version: "0.11.1", Locations: []types.Location{{StartLine: 12307, EndLine: 12310}}},
		{ID: "regenerator-runtime@0.12.1", Name: "regenerator-runtime", Version: "0.12.1", Locations: []types.Location{{StartLine: 12312, EndLine: 12315}}},
		{ID: "regenerator-runtime@0.13.2", Name: "regenerator-runtime", Version: "0.13.2", Locations: []types.Location{{StartLine: 12317, EndLine: 12320}}},
		{ID: "regenerator-transform@0.10.1", Name: "regenerator-transform", Version: "0.10.1", Locations: []types.Location{{StartLine: 12322, EndLine: 12329}}},
		{ID: "regenerator-transform@0.13.4", Name: "regenerator-transform", Version: "0.13.4", Locations: []types.Location{{StartLine: 12331, EndLine: 12336}}},
		{ID: "regex-cache@0.4.4", Name: "regex-cache", Version: "0.4.4", Locations: []types.Location{{StartLine: 12338, EndLine: 12343}}},
		{ID: "regex-not@1.0.2", Name: "regex-not", Version: "1.0.2", Locations: []types.Location{{StartLine: 12345, EndLine: 12351}}},
		{ID: "regexp-tree@0.1.6", Name: "regexp-tree", Version: "0.1.6", Locations: []types.Location{{StartLine: 12353, EndLine: 12356}}},
		{ID: "regexp.prototype.flags@1.2.0", Name: "regexp.prototype.flags", Version: "1.2.0", Locations: []types.Location{{StartLine: 12358, EndLine: 12363}}},
		{ID: "regexpp@2.0.1", Name: "regexpp", Version: "2.0.1", Locations: []types.Location{{StartLine: 12365, EndLine: 12368}}},
		{ID: "regexpu-core@1.0.0", Name: "regexpu-core", Version: "1.0.0", Locations: []types.Location{{StartLine: 12370, EndLine: 12377}}},
		{ID: "regexpu-core@2.0.0", Name: "regexpu-core", Version: "2.0.0", Locations: []types.Location{{StartLine: 12379, EndLine: 12386}}},
		{ID: "regexpu-core@4.5.4", Name: "regexpu-core", Version: "4.5.4", Locations: []types.Location{{StartLine: 12388, EndLine: 12398}}},
		{ID: "registry-auth-token@3.4.0", Name: "registry-auth-token", Version: "3.4.0", Locations: []types.Location{{StartLine: 12400, EndLine: 12406}}},
		{ID: "registry-url@3.1.0", Name: "registry-url", Version: "3.1.0", Locations: []types.Location{{StartLine: 12408, EndLine: 12413}}},
		{ID: "regjsgen@0.2.0", Name: "regjsgen", Version: "0.2.0", Locations: []types.Location{{StartLine: 12415, EndLine: 12418}}},
		{ID: "regjsgen@0.5.0", Name: "regjsgen", Version: "0.5.0", Locations: []types.Location{{StartLine: 12420, EndLine: 12423}}},
		{ID: "regjsparser@0.1.5", Name: "regjsparser", Version: "0.1.5", Locations: []types.Location{{StartLine: 12425, EndLine: 12430}}},
		{ID: "regjsparser@0.6.0", Name: "regjsparser", Version: "0.6.0", Locations: []types.Location{{StartLine: 12432, EndLine: 12437}}},
		{ID: "rehype-parse@6.0.0", Name: "rehype-parse", Version: "6.0.0", Locations: []types.Location{{StartLine: 12439, EndLine: 12446}}},
		{ID: "relateurl@0.2.7", Name: "relateurl", Version: "0.2.7", Locations: []types.Location{{StartLine: 12448, EndLine: 12451}}},
		{ID: "remove-trailing-separator@1.1.0", Name: "remove-trailing-separator", Version: "1.1.0", Locations: []types.Location{{StartLine: 12453, EndLine: 12456}}},
		{ID: "render-fragment@0.1.1", Name: "render-fragment", Version: "0.1.1", Locations: []types.Location{{StartLine: 12458, EndLine: 12461}}},
		{ID: "renderkid@2.0.3", Name: "renderkid", Version: "2.0.3", Locations: []types.Location{{StartLine: 12463, EndLine: 12472}}},
		{ID: "repeat-element@1.1.3", Name: "repeat-element", Version: "1.1.3", Locations: []types.Location{{StartLine: 12474, EndLine: 12477}}},
		{ID: "repeat-string@1.6.1", Name: "repeat-string", Version: "1.6.1", Locations: []types.Location{{StartLine: 12479, EndLine: 12482}}},
		{ID: "repeating@2.0.1", Name: "repeating", Version: "2.0.1", Locations: []types.Location{{StartLine: 12484, EndLine: 12489}}},
		{ID: "replace-ext@1.0.0", Name: "replace-ext", Version: "1.0.0", Locations: []types.Location{{StartLine: 12491, EndLine: 12494}}},
		{ID: "request-promise-core@1.1.2", Name: "request-promise-core", Version: "1.1.2", Locations: []types.Location{{StartLine: 12496, EndLine: 12501}}},
		{ID: "request-promise-native@1.0.7", Name: "request-promise-native", Version: "1.0.7", Locations: []types.Location{{StartLine: 12503, EndLine: 12510}}},
		{ID: "request@2.88.0", Name: "request", Version: "2.88.0", Locations: []types.Location{{StartLine: 12512, EndLine: 12536}}},
		{ID: "require-directory@2.1.1", Name: "require-directory", Version: "2.1.1", Locations: []types.Location{{StartLine: 12538, EndLine: 12541}}},
		{ID: "require-from-string@2.0.2", Name: "require-from-string", Version: "2.0.2", Locations: []types.Location{{StartLine: 12543, EndLine: 12546}}},
		{ID: "require-main-filename@1.0.1", Name: "require-main-filename", Version: "1.0.1", Locations: []types.Location{{StartLine: 12548, EndLine: 12551}}},
		{ID: "requires-port@1.0.0", Name: "requires-port", Version: "1.0.0", Locations: []types.Location{{StartLine: 12553, EndLine: 12556}}},
		{ID: "resolve-cwd@2.0.0", Name: "resolve-cwd", Version: "2.0.0", Locations: []types.Location{{StartLine: 12558, EndLine: 12563}}},
		{ID: "resolve-dir@1.0.1", Name: "resolve-dir", Version: "1.0.1", Locations: []types.Location{{StartLine: 12565, EndLine: 12571}}},
		{ID: "resolve-from@3.0.0", Name: "resolve-from", Version: "3.0.0", Locations: []types.Location{{StartLine: 12573, EndLine: 12576}}},
		{ID: "resolve-from@4.0.0", Name: "resolve-from", Version: "4.0.0", Locations: []types.Location{{StartLine: 12578, EndLine: 12581}}},
		{ID: "resolve-pathname@2.2.0", Name: "resolve-pathname", Version: "2.2.0", Locations: []types.Location{{StartLine: 12583, EndLine: 12586}}},
		{ID: "resolve-url@0.2.1", Name: "resolve-url", Version: "0.2.1", Locations: []types.Location{{StartLine: 12588, EndLine: 12591}}},
		{ID: "resolve@1.1.7", Name: "resolve", Version: "1.1.7", Locations: []types.Location{{StartLine: 12593, EndLine: 12596}}},
		{ID: "resolve@1.10.1", Name: "resolve", Version: "1.10.1", Locations: []types.Location{{StartLine: 12598, EndLine: 12603}}},
		{ID: "restore-cursor@1.0.1", Name: "restore-cursor", Version: "1.0.1", Locations: []types.Location{{StartLine: 12605, EndLine: 12611}}},
		{ID: "restore-cursor@2.0.0", Name: "restore-cursor", Version: "2.0.0", Locations: []types.Location{{StartLine: 12613, EndLine: 12619}}},
		{ID: "ret@0.1.15", Name: "ret", Version: "0.1.15", Locations: []types.Location{{StartLine: 12621, EndLine: 12624}}},
		{ID: "retry@0.10.1", Name: "retry", Version: "0.10.1", Locations: []types.Location{{StartLine: 12626, EndLine: 12629}}},
		{ID: "retry@0.12.0", Name: "retry", Version: "0.12.0", Locations: []types.Location{{StartLine: 12631, EndLine: 12634}}},
		{ID: "rimraf@2.6.3", Name: "rimraf", Version: "2.6.3", Locations: []types.Location{{StartLine: 12636, EndLine: 12641}}},
		{ID: "rimraf@2.2.8", Name: "rimraf", Version: "2.2.8", Locations: []types.Location{{StartLine: 12643, EndLine: 12646}}},
		{ID: "ripemd160@2.0.2", Name: "ripemd160", Version: "2.0.2", Locations: []types.Location{{StartLine: 12648, EndLine: 12654}}},
		{ID: "rst-selector-parser@2.2.3", Name: "rst-selector-parser", Version: "2.2.3", Locations: []types.Location{{StartLine: 12656, EndLine: 12662}}},
		{ID: "rsvp@3.6.2", Name: "rsvp", Version: "3.6.2", Locations: []types.Location{{StartLine: 12664, EndLine: 12667}}},
		{ID: "run-async@0.1.0", Name: "run-async", Version: "0.1.0", Locations: []types.Location{{StartLine: 12669, EndLine: 12674}}},
		{ID: "run-async@2.3.0", Name: "run-async", Version: "2.3.0", Locations: []types.Location{{StartLine: 12676, EndLine: 12681}}},
		{ID: "run-node@1.0.0", Name: "run-node", Version: "1.0.0", Locations: []types.Location{{StartLine: 12683, EndLine: 12686}}},
		{ID: "run-queue@1.0.3", Name: "run-queue", Version: "1.0.3", Locations: []types.Location{{StartLine: 12688, EndLine: 12693}}},
		{ID: "rx-lite@3.1.2", Name: "rx-lite", Version: "3.1.2", Locations: []types.Location{{StartLine: 12695, EndLine: 12698}}},
		{ID: "rxjs@6.5.2", Name: "rxjs", Version: "6.5.2", Locations: []types.Location{{StartLine: 12700, EndLine: 12705}}},
		{ID: "safe-buffer@5.1.1", Name: "safe-buffer", Version: "5.1.1", Locations: []types.Location{{StartLine: 12707, EndLine: 12710}}},
		{ID: "safe-buffer@5.1.2", Name: "safe-buffer", Version: "5.1.2", Locations: []types.Location{{StartLine: 12712, EndLine: 12715}}},
		{ID: "safe-regex@1.1.0", Name: "safe-regex", Version: "1.1.0", Locations: []types.Location{{StartLine: 12717, EndLine: 12722}}},
		{ID: "safer-buffer@2.1.2", Name: "safer-buffer", Version: "2.1.2", Locations: []types.Location{{StartLine: 12724, EndLine: 12727}}},
		{ID: "sane@2.5.2", Name: "sane", Version: "2.5.2", Locations: []types.Location{{StartLine: 12729, EndLine: 12743}}},
		{ID: "sax@1.2.4", Name: "sax", Version: "1.2.4", Locations: []types.Location{{StartLine: 12745, EndLine: 12748}}},
		{ID: "scheduler@0.13.6", Name: "scheduler", Version: "0.13.6", Locations: []types.Location{{StartLine: 12750, EndLine: 12756}}},
		{ID: "schema-utils@0.4.7", Name: "schema-utils", Version: "0.4.7", Locations: []types.Location{{StartLine: 12758, EndLine: 12764}}},
		{ID: "schema-utils@1.0.0", Name: "schema-utils", Version: "1.0.0", Locations: []types.Location{{StartLine: 12766, EndLine: 12773}}},
		{ID: "select-hose@2.0.0", Name: "select-hose", Version: "2.0.0", Locations: []types.Location{{StartLine: 12775, EndLine: 12778}}},
		{ID: "selfsigned@1.10.4", Name: "selfsigned", Version: "1.10.4", Locations: []types.Location{{StartLine: 12780, EndLine: 12785}}},
		{ID: "semver-compare@1.0.0", Name: "semver-compare", Version: "1.0.0", Locations: []types.Location{{StartLine: 12787, EndLine: 12790}}},
		{ID: "semver-diff@2.1.0", Name: "semver-diff", Version: "2.1.0", Locations: []types.Location{{StartLine: 12792, EndLine: 12797}}},
		{ID: "semver@5.7.0", Name: "semver", Version: "5.7.0", Locations: []types.Location{{StartLine: 12799, EndLine: 12802}}},
		{ID: "semver@6.0.0", Name: "semver", Version: "6.0.0", Locations: []types.Location{{StartLine: 12804, EndLine: 12807}}},
		{ID: "semver@5.3.0", Name: "semver", Version: "5.3.0", Locations: []types.Location{{StartLine: 12809, EndLine: 12812}}},
		{ID: "send@0.16.2", Name: "send", Version: "0.16.2", Locations: []types.Location{{StartLine: 12814, EndLine: 12831}}},
		{ID: "serialize-javascript@1.7.0", Name: "serialize-javascript", Version: "1.7.0", Locations: []types.Location{{StartLine: 12833, EndLine: 12836}}},
		{ID: "serve-favicon@2.5.0", Name: "serve-favicon", Version: "2.5.0", Locations: []types.Location{{StartLine: 12838, EndLine: 12847}}},
		{ID: "serve-index@1.9.1", Name: "serve-index", Version: "1.9.1", Locations: []types.Location{{StartLine: 12849, EndLine: 12860}}},
		{ID: "serve-static@1.13.2", Name: "serve-static", Version: "1.13.2", Locations: []types.Location{{StartLine: 12862, EndLine: 12870}}},
		{ID: "set-blocking@2.0.0", Name: "set-blocking", Version: "2.0.0", Locations: []types.Location{{StartLine: 12872, EndLine: 12875}}},
		{ID: "set-value@0.4.3", Name: "set-value", Version: "0.4.3", Locations: []types.Location{{StartLine: 12877, EndLine: 12885}}},
		{ID: "set-value@2.0.0", Name: "set-value", Version: "2.0.0", Locations: []types.Location{{StartLine: 12887, EndLine: 12895}}},
		{ID: "setimmediate@1.0.5", Name: "setimmediate", Version: "1.0.5", Locations: []types.Location{{StartLine: 12897, EndLine: 12900}}},
		{ID: "setprototypeof@1.1.0", Name: "setprototypeof", Version: "1.1.0", Locations: []types.Location{{StartLine: 12902, EndLine: 12905}}},
		{ID: "sha.js@2.4.11", Name: "sha.js", Version: "2.4.11", Locations: []types.Location{{StartLine: 12907, EndLine: 12913}}},
		{ID: "sha@2.0.1", Name: "sha", Version: "2.0.1", Locations: []types.Location{{StartLine: 12915, EndLine: 12921}}},
		{ID: "shallow-clone@0.1.2", Name: "shallow-clone", Version: "0.1.2", Locations: []types.Location{{StartLine: 12923, EndLine: 12931}}},
		{ID: "shallowequal@1.1.0", Name: "shallowequal", Version: "1.1.0", Locations: []types.Location{{StartLine: 12933, EndLine: 12936}}},
		{ID: "shebang-command@1.2.0", Name: "shebang-command", Version: "1.2.0", Locations: []types.Location{{StartLine: 12938, EndLine: 12943}}},
		{ID: "shebang-regex@1.0.0", Name: "shebang-regex", Version: "1.0.0", Locations: []types.Location{{StartLine: 12945, EndLine: 12948}}},
		{ID: "shell-quote@1.6.1", Name: "shell-quote", Version: "1.6.1", Locations: []types.Location{{StartLine: 12950, EndLine: 12958}}},
		{ID: "shelljs@0.8.3", Name: "shelljs", Version: "0.8.3", Locations: []types.Location{{StartLine: 12960, EndLine: 12967}}},
		{ID: "shellwords@0.1.1", Name: "shellwords", Version: "0.1.1", Locations: []types.Location{{StartLine: 12969, EndLine: 12972}}},
		{ID: "signal-exit@3.0.2", Name: "signal-exit", Version: "3.0.2", Locations: []types.Location{{StartLine: 12974, EndLine: 12977}}},
		{ID: "sisteransi@0.1.1", Name: "sisteransi", Version: "0.1.1", Locations: []types.Location{{StartLine: 12979, EndLine: 12982}}},
		{ID: "slash@1.0.0", Name: "slash", Version: "1.0.0", Locations: []types.Location{{StartLine: 12984, EndLine: 12987}}},
		{ID: "slash@2.0.0", Name: "slash", Version: "2.0.0", Locations: []types.Location{{StartLine: 12989, EndLine: 12992}}},
		{ID: "slice-ansi@0.0.4", Name: "slice-ansi", Version: "0.0.4", Locations: []types.Location{{StartLine: 12994, EndLine: 12997}}},
		{ID: "slice-ansi@1.0.0", Name: "slice-ansi", Version: "1.0.0", Locations: []types.Location{{StartLine: 12999, EndLine: 13004}}},
		{ID: "slice-ansi@2.1.0", Name: "slice-ansi", Version: "2.1.0", Locations: []types.Location{{StartLine: 13006, EndLine: 13013}}},
		{ID: "slide@1.1.6", Name: "slide", Version: "1.1.6", Locations: []types.Location{{StartLine: 13015, EndLine: 13018}}},
		{ID: "smart-buffer@4.0.2", Name: "smart-buffer", Version: "4.0.2", Locations: []types.Location{{StartLine: 13020, EndLine: 13023}}},
		{ID: "snapdragon-node@2.1.1", Name: "snapdragon-node", Version: "2.1.1", Locations: []types.Location{{StartLine: 13025, EndLine: 13032}}},
		{ID: "snapdragon-util@3.0.1", Name: "snapdragon-util", Version: "3.0.1", Locations: []types.Location{{StartLine: 13034, EndLine: 13039}}},
		{ID: "snapdragon@0.8.2", Name: "snapdragon", Version: "0.8.2", Locations: []types.Location{{StartLine: 13041, EndLine: 13053}}},
		{ID: "socket.io-adapter@1.1.1", Name: "socket.io-adapter", Version: "1.1.1", Locations: []types.Location{{StartLine: 13055, EndLine: 13058}}},
		{ID: "socket.io-client@2.2.0", Name: "socket.io-client", Version: "2.2.0", Locations: []types.Location{{StartLine: 13060, EndLine: 13078}}},
		{ID: "socket.io-parser@3.3.0", Name: "socket.io-parser", Version: "3.3.0", Locations: []types.Location{{StartLine: 13080, EndLine: 13087}}},
		{ID: "socket.io@2.2.0", Name: "socket.io", Version: "2.2.0", Locations: []types.Location{{StartLine: 13089, EndLine: 13099}}},
		{ID: "sockjs-client@1.1.5", Name: "sockjs-client", Version: "1.1.5", Locations: []types.Location{{StartLine: 13101, EndLine: 13111}}},
		{ID: "sockjs-client@1.3.0", Name: "sockjs-client", Version: "1.3.0", Locations: []types.Location{{StartLine: 13113, EndLine: 13123}}},
		{ID: "sockjs@0.3.19", Name: "sockjs", Version: "0.3.19", Locations: []types.Location{{StartLine: 13125, EndLine: 13131}}},
		{ID: "socks-proxy-agent@4.0.2", Name: "socks-proxy-agent", Version: "4.0.2", Locations: []types.Location{{StartLine: 13133, EndLine: 13139}}},
		{ID: "socks@2.3.2", Name: "socks", Version: "2.3.2", Locations: []types.Location{{StartLine: 13141, EndLine: 13147}}},
		{ID: "sort-keys@2.0.0", Name: "sort-keys", Version: "2.0.0", Locations: []types.Location{{StartLine: 13149, EndLine: 13154}}},
		{ID: "sorted-object@2.0.1", Name: "sorted-object", Version: "2.0.1", Locations: []types.Location{{StartLine: 13156, EndLine: 13159}}},
		{ID: "sorted-union-stream@2.1.3", Name: "sorted-union-stream", Version: "2.1.3", Locations: []types.Location{{StartLine: 13161, EndLine: 13167}}},
		{ID: "source-list-map@2.0.1", Name: "source-list-map", Version: "2.0.1", Locations: []types.Location{{StartLine: 13169, EndLine: 13172}}},
		{ID: "source-map-resolve@0.5.2", Name: "source-map-resolve", Version: "0.5.2", Locations: []types.Location{{StartLine: 13174, EndLine: 13183}}},
		{ID: "source-map-support@0.4.18", Name: "source-map-support", Version: "0.4.18", Locations: []types.Location{{StartLine: 13185, EndLine: 13190}}},
		{ID: "source-map-support@0.5.12", Name: "source-map-support", Version: "0.5.12", Locations: []types.Location{{StartLine: 13192, EndLine: 13198}}},
		{ID: "source-map-url@0.4.0", Name: "source-map-url", Version: "0.4.0", Locations: []types.Location{{StartLine: 13200, EndLine: 13203}}},
		{ID: "source-map@0.5.7", Name: "source-map", Version: "0.5.7", Locations: []types.Location{{StartLine: 13205, EndLine: 13208}}},
		{ID: "source-map@0.6.1", Name: "source-map", Version: "0.6.1", Locations: []types.Location{{StartLine: 13210, EndLine: 13213}}},
		{ID: "space-separated-tokens@1.1.4", Name: "space-separated-tokens", Version: "1.1.4", Locations: []types.Location{{StartLine: 13215, EndLine: 13218}}},
		{ID: "spawn-promise@0.1.8", Name: "spawn-promise", Version: "0.1.8", Locations: []types.Location{{StartLine: 13220, EndLine: 13225}}},
		{ID: "spdx-correct@3.1.0", Name: "spdx-correct", Version: "3.1.0", Locations: []types.Location{{StartLine: 13227, EndLine: 13233}}},
		{ID: "spdx-exceptions@2.2.0", Name: "spdx-exceptions", Version: "2.2.0", Locations: []types.Location{{StartLine: 13235, EndLine: 13238}}},
		{ID: "spdx-expression-parse@3.0.0", Name: "spdx-expression-parse", Version: "3.0.0", Locations: []types.Location{{StartLine: 13240, EndLine: 13246}}},
		{ID: "spdx-license-ids@3.0.4", Name: "spdx-license-ids", Version: "3.0.4", Locations: []types.Location{{StartLine: 13248, EndLine: 13251}}},
		{ID: "spdy-transport@3.0.0", Name: "spdy-transport", Version: "3.0.0", Locations: []types.Location{{StartLine: 13253, EndLine: 13263}}},
		{ID: "spdy@4.0.0", Name: "spdy", Version: "4.0.0", Locations: []types.Location{{StartLine: 13265, EndLine: 13274}}},
		{ID: "split-on-first@1.1.0", Name: "split-on-first", Version: "1.1.0", Locations: []types.Location{{StartLine: 13276, EndLine: 13279}}},
		{ID: "split-string@3.1.0", Name: "split-string", Version: "3.1.0", Locations: []types.Location{{StartLine: 13281, EndLine: 13286}}},
		{ID: "sprintf-js@1.0.3", Name: "sprintf-js", Version: "1.0.3", Locations: []types.Location{{StartLine: 13288, EndLine: 13291}}},
		{ID: "sshpk@1.16.1", Name: "sshpk", Version: "1.16.1", Locations: []types.Location{{StartLine: 13293, EndLine: 13306}}},
		{ID: "ssri@5.3.0", Name: "ssri", Version: "5.3.0", Locations: []types.Location{{StartLine: 13308, EndLine: 13313}}},
		{ID: "ssri@6.0.1", Name: "ssri", Version: "6.0.1", Locations: []types.Location{{StartLine: 13315, EndLine: 13320}}},
		{ID: "stable@0.1.8", Name: "stable", Version: "0.1.8", Locations: []types.Location{{StartLine: 13322, EndLine: 13325}}},
		{ID: "stack-utils@1.0.2", Name: "stack-utils", Version: "1.0.2", Locations: []types.Location{{StartLine: 13327, EndLine: 13330}}},
		{ID: "staged-git-files@1.1.1", Name: "staged-git-files", Version: "1.1.1", Locations: []types.Location{{StartLine: 13332, EndLine: 13335}}},
		{ID: "static-extend@0.1.2", Name: "static-extend", Version: "0.1.2", Locations: []types.Location{{StartLine: 13337, EndLine: 13343}}},
		{ID: "statuses@1.5.0", Name: "statuses", Version: "1.5.0", Locations: []types.Location{{StartLine: 13345, EndLine: 13348}}},
		{ID: "statuses@1.4.0", Name: "statuses", Version: "1.4.0", Locations: []types.Location{{StartLine: 13350, EndLine: 13353}}},
		{ID: "stealthy-require@1.1.1", Name: "stealthy-require", Version: "1.1.1", Locations: []types.Location{{StartLine: 13355, EndLine: 13358}}},
		{ID: "stream-browserify@2.0.2", Name: "stream-browserify", Version: "2.0.2", Locations: []types.Location{{StartLine: 13360, EndLine: 13366}}},
		{ID: "stream-each@1.2.3", Name: "stream-each", Version: "1.2.3", Locations: []types.Location{{StartLine: 13368, EndLine: 13374}}},
		{ID: "stream-http@2.8.3", Name: "stream-http", Version: "2.8.3", Locations: []types.Location{{StartLine: 13376, EndLine: 13385}}},
		{ID: "stream-iterate@1.2.0", Name: "stream-iterate", Version: "1.2.0", Locations: []types.Location{{StartLine: 13387, EndLine: 13393}}},
		{ID: "stream-shift@1.0.0", Name: "stream-shift", Version: "1.0.0", Locations: []types.Location{{StartLine: 13395, EndLine: 13398}}},
		{ID: "strict-uri-encode@2.0.0", Name: "strict-uri-encode", Version: "2.0.0", Locations: []types.Location{{StartLine: 13400, EndLine: 13403}}},
		{ID: "string-argv@0.0.2", Name: "string-argv", Version: "0.0.2", Locations: []types.Location{{StartLine: 13405, EndLine: 13408}}},
		{ID: "string-length@2.0.0", Name: "string-length", Version: "2.0.0", Locations: []types.Location{{StartLine: 13410, EndLine: 13416}}},
		{ID: "string-width@1.0.2", Name: "string-width", Version: "1.0.2", Locations: []types.Location{{StartLine: 13418, EndLine: 13425}}},
		{ID: "string-width@2.1.1", Name: "string-width", Version: "2.1.1", Locations: []types.Location{{StartLine: 13427, EndLine: 13433}}},
		{ID: "string-width@3.1.0", Name: "string-width", Version: "3.1.0", Locations: []types.Location{{StartLine: 13435, EndLine: 13442}}},
		{ID: "string.prototype.matchall@3.0.1", Name: "string.prototype.matchall", Version: "3.0.1", Locations: []types.Location{{StartLine: 13444, EndLine: 13453}}},
		{ID: "string.prototype.padend@3.0.0", Name: "string.prototype.padend", Version: "3.0.0", Locations: []types.Location{{StartLine: 13455, EndLine: 13462}}},
		{ID: "string.prototype.padstart@3.0.0", Name: "string.prototype.padstart", Version: "3.0.0", Locations: []types.Location{{StartLine: 13464, EndLine: 13471}}},
		{ID: "string.prototype.trim@1.1.2", Name: "string.prototype.trim", Version: "1.1.2", Locations: []types.Location{{StartLine: 13473, EndLine: 13480}}},
		{ID: "string_decoder@1.2.0", Name: "string_decoder", Version: "1.2.0", Locations: []types.Location{{StartLine: 13482, EndLine: 13487}}},
		{ID: "string_decoder@0.10.31", Name: "string_decoder", Version: "0.10.31", Locations: []types.Location{{StartLine: 13489, EndLine: 13492}}},
		{ID: "string_decoder@1.1.1", Name: "string_decoder", Version: "1.1.1", Locations: []types.Location{{StartLine: 13494, EndLine: 13499}}},
		{ID: "stringify-object@3.3.0", Name: "stringify-object", Version: "3.3.0", Locations: []types.Location{{StartLine: 13501, EndLine: 13508}}},
		{ID: "stringify-package@1.0.0", Name: "stringify-package", Version: "1.0.0", Locations: []types.Location{{StartLine: 13510, EndLine: 13513}}},
		{ID: "strip-ansi@4.0.0", Name: "strip-ansi", Version: "4.0.0", Locations: []types.Location{{StartLine: 13515, EndLine: 13520}}},
		{ID: "strip-ansi@3.0.1", Name: "strip-ansi", Version: "3.0.1", Locations: []types.Location{{StartLine: 13522, EndLine: 13527}}},
		{ID: "strip-ansi@5.2.0", Name: "strip-ansi", Version: "5.2.0", Locations: []types.Location{{StartLine: 13529, EndLine: 13534}}},
		{ID: "strip-ansi@0.1.1", Name: "strip-ansi", Version: "0.1.1", Locations: []types.Location{{StartLine: 13536, EndLine: 13539}}},
		{ID: "strip-bom@3.0.0", Name: "strip-bom", Version: "3.0.0", Locations: []types.Location{{StartLine: 13541, EndLine: 13544}}},
		{ID: "strip-bom@2.0.0", Name: "strip-bom", Version: "2.0.0", Locations: []types.Location{{StartLine: 13546, EndLine: 13551}}},
		{ID: "strip-eof@1.0.0", Name: "strip-eof", Version: "1.0.0", Locations: []types.Location{{StartLine: 13553, EndLine: 13556}}},
		{ID: "strip-json-comments@2.0.1", Name: "strip-json-comments", Version: "2.0.1", Locations: []types.Location{{StartLine: 13558, EndLine: 13561}}},
		{ID: "style-loader@0.23.1", Name: "style-loader", Version: "0.23.1", Locations: []types.Location{{StartLine: 13563, EndLine: 13569}}},
		{ID: "styled-components@4.1.3", Name: "styled-components", Version: "4.1.3", Locations: []types.Location{{StartLine: 13571, EndLine: 13586}}},
		{ID: "stylis-rule-sheet@0.0.10", Name: "stylis-rule-sheet", Version: "0.0.10", Locations: []types.Location{{StartLine: 13588, EndLine: 13591}}},
		{ID: "stylis@3.5.4", Name: "stylis", Version: "3.5.4", Locations: []types.Location{{StartLine: 13593, EndLine: 13596}}},
		{ID: "supports-color@2.0.0", Name: "supports-color", Version: "2.0.0", Locations: []types.Location{{StartLine: 13598, EndLine: 13601}}},
		{ID: "supports-color@3.2.3", Name: "supports-color", Version: "3.2.3", Locations: []types.Location{{StartLine: 13603, EndLine: 13608}}},
		{ID: "supports-color@5.5.0", Name: "supports-color", Version: "5.5.0", Locations: []types.Location{{StartLine: 13610, EndLine: 13615}}},
		{ID: "supports-color@6.1.0", Name: "supports-color", Version: "6.1.0", Locations: []types.Location{{StartLine: 13617, EndLine: 13622}}},
		{ID: "svg-url-loader@2.3.2", Name: "svg-url-loader", Version: "2.3.2", Locations: []types.Location{{StartLine: 13624, EndLine: 13630}}},
		{ID: "svgo@1.2.2", Name: "svgo", Version: "1.2.2", Locations: []types.Location{{StartLine: 13632, EndLine: 13650}}},
		{ID: "symbol-observable@1.2.0", Name: "symbol-observable", Version: "1.2.0", Locations: []types.Location{{StartLine: 13652, EndLine: 13655}}},
		{ID: "symbol-tree@3.2.2", Name: "symbol-tree", Version: "3.2.2", Locations: []types.Location{{StartLine: 13657, EndLine: 13660}}},
		{ID: "symbol.prototype.description@1.0.0", Name: "symbol.prototype.description", Version: "1.0.0", Locations: []types.Location{{StartLine: 13662, EndLine: 13667}}},
		{ID: "table@4.0.3", Name: "table", Version: "4.0.3", Locations: []types.Location{{StartLine: 13669, EndLine: 13679}}},
		{ID: "table@5.3.3", Name: "table", Version: "5.3.3", Locations: []types.Location{{StartLine: 13681, EndLine: 13689}}},
		{ID: "tapable@1.1.3", Name: "tapable", Version: "1.1.3", Locations: []types.Location{{StartLine: 13691, EndLine: 13694}}},
		{ID: "tar@2.2.2", Name: "tar", Version: "2.2.2", Locations: []types.Location{{StartLine: 13696, EndLine: 13703}}},
		{ID: "tar@4.4.8", Name: "tar", Version: "4.4.8", Locations: []types.Location{{StartLine: 13705, EndLine: 13716}}},
		{ID: "temp@0.8.3", Name: "temp", Version: "0.8.3", Locations: []types.Location{{StartLine: 13718, EndLine: 13724}}},
		{ID: "term-size@1.2.0", Name: "term-size", Version: "1.2.0", Locations: []types.Location{{StartLine: 13726, EndLine: 13731}}},
		{ID: "terser-webpack-plugin@1.2.4", Name: "terser-webpack-plugin", Version: "1.2.4", Locations: []types.Location{{StartLine: 13733, EndLine: 13746}}},
		{ID: "terser@3.17.0", Name: "terser", Version: "3.17.0", Locations: []types.Location{{StartLine: 13748, EndLine: 13755}}},
		{ID: "test-exclude@4.2.3", Name: "test-exclude", Version: "4.2.3", Locations: []types.Location{{StartLine: 13757, EndLine: 13766}}},
		{ID: "text-table@0.2.0", Name: "text-table", Version: "0.2.0", Locations: []types.Location{{StartLine: 13768, EndLine: 13771}}},
		{ID: "throat@4.1.0", Name: "throat", Version: "4.1.0", Locations: []types.Location{{StartLine: 13773, EndLine: 13776}}},
		{ID: "through2@2.0.5", Name: "through2", Version: "2.0.5", Locations: []types.Location{{StartLine: 13778, EndLine: 13784}}},
		{ID: "through@2.3.8", Name: "through", Version: "2.3.8", Locations: []types.Location{{StartLine: 13786, EndLine: 13789}}},
		{ID: "thunky@1.0.3", Name: "thunky", Version: "1.0.3", Locations: []types.Location{{StartLine: 13791, EndLine: 13794}}},
		{ID: "timed-out@4.0.1", Name: "timed-out", Version: "4.0.1", Locations: []types.Location{{StartLine: 13796, EndLine: 13799}}},
		{ID: "timers-browserify@2.0.10", Name: "timers-browserify", Version: "2.0.10", Locations: []types.Location{{StartLine: 13801, EndLine: 13806}}},
		{ID: "tiny-invariant@1.0.4", Name: "tiny-invariant", Version: "1.0.4", Locations: []types.Location{{StartLine: 13808, EndLine: 13811}}},
		{ID: "tiny-relative-date@1.3.0", Name: "tiny-relative-date", Version: "1.3.0", Locations: []types.Location{{StartLine: 13813, EndLine: 13816}}},
		{ID: "tiny-warning@1.0.2", Name: "tiny-warning", Version: "1.0.2", Locations: []types.Location{{StartLine: 13818, EndLine: 13821}}},
		{ID: "tinycolor2@1.4.1", Name: "tinycolor2", Version: "1.4.1", Locations: []types.Location{{StartLine: 13823, EndLine: 13826}}},
		{ID: "tmp@0.0.33", Name: "tmp", Version: "0.0.33", Locations: []types.Location{{StartLine: 13828, EndLine: 13833}}},
		{ID: "tmpl@1.0.4", Name: "tmpl", Version: "1.0.4", Locations: []types.Location{{StartLine: 13835, EndLine: 13838}}},
		{ID: "to-array@0.1.4", Name: "to-array", Version: "0.1.4", Locations: []types.Location{{StartLine: 13840, EndLine: 13843}}},
		{ID: "to-arraybuffer@1.0.1", Name: "to-arraybuffer", Version: "1.0.1", Locations: []types.Location{{StartLine: 13845, EndLine: 13848}}},
		{ID: "to-fast-properties@1.0.3", Name: "to-fast-properties", Version: "1.0.3", Locations: []types.Location{{StartLine: 13850, EndLine: 13853}}},
		{ID: "to-fast-properties@2.0.0", Name: "to-fast-properties", Version: "2.0.0", Locations: []types.Location{{StartLine: 13855, EndLine: 13858}}},
		{ID: "to-object-path@0.3.0", Name: "to-object-path", Version: "0.3.0", Locations: []types.Location{{StartLine: 13860, EndLine: 13865}}},
		{ID: "to-regex-range@2.1.1", Name: "to-regex-range", Version: "2.1.1", Locations: []types.Location{{StartLine: 13867, EndLine: 13873}}},
		{ID: "to-regex@3.0.2", Name: "to-regex", Version: "3.0.2", Locations: []types.Location{{StartLine: 13875, EndLine: 13883}}},
		{ID: "toggle-selection@1.0.6", Name: "toggle-selection", Version: "1.0.6", Locations: []types.Location{{StartLine: 13885, EndLine: 13888}}},
		{ID: "toposort@1.0.7", Name: "toposort", Version: "1.0.7", Locations: []types.Location{{StartLine: 13890, EndLine: 13893}}},
		{ID: "tough-cookie@2.5.0", Name: "tough-cookie", Version: "2.5.0", Locations: []types.Location{{StartLine: 13895, EndLine: 13901}}},
		{ID: "tough-cookie@2.4.3", Name: "tough-cookie", Version: "2.4.3", Locations: []types.Location{{StartLine: 13903, EndLine: 13909}}},
		{ID: "tr46@1.0.1", Name: "tr46", Version: "1.0.1", Locations: []types.Location{{StartLine: 13911, EndLine: 13916}}},
		{ID: "traverse@0.3.9", Name: "traverse", Version: "0.3.9", Locations: []types.Location{{StartLine: 13918, EndLine: 13921}}},
		{ID: "trim-right@1.0.1", Name: "trim-right", Version: "1.0.1", Locations: []types.Location{{StartLine: 13923, EndLine: 13926}}},
		{ID: "trough@1.0.4", Name: "trough", Version: "1.0.4", Locations: []types.Location{{StartLine: 13928, EndLine: 13931}}},
		{ID: "tryer@1.0.1", Name: "tryer", Version: "1.0.1", Locations: []types.Location{{StartLine: 13933, EndLine: 13936}}},
		{ID: "tslib@1.9.3", Name: "tslib", Version: "1.9.3", Locations: []types.Location{{StartLine: 13938, EndLine: 13941}}},
		{ID: "tty-browserify@0.0.0", Name: "tty-browserify", Version: "0.0.0", Locations: []types.Location{{StartLine: 13943, EndLine: 13946}}},
		{ID: "tunnel-agent@0.6.0", Name: "tunnel-agent", Version: "0.6.0", Locations: []types.Location{{StartLine: 13948, EndLine: 13953}}},
		{ID: "tweetnacl@0.14.5", Name: "tweetnacl", Version: "0.14.5", Locations: []types.Location{{StartLine: 13955, EndLine: 13958}}},
		{ID: "type-check@0.3.2", Name: "type-check", Version: "0.3.2", Locations: []types.Location{{StartLine: 13960, EndLine: 13965}}},
		{ID: "type-is@1.6.18", Name: "type-is", Version: "1.6.18", Locations: []types.Location{{StartLine: 13967, EndLine: 13973}}},
		{ID: "typed-styles@0.0.7", Name: "typed-styles", Version: "0.0.7", Locations: []types.Location{{StartLine: 13975, EndLine: 13978}}},
		{ID: "typedarray@0.0.6", Name: "typedarray", Version: "0.0.6", Locations: []types.Location{{StartLine: 13980, EndLine: 13983}}},
		{ID: "ua-parser-js@0.7.19", Name: "ua-parser-js", Version: "0.7.19", Locations: []types.Location{{StartLine: 13985, EndLine: 13988}}},
		{ID: "uglify-js@3.4.10", Name: "uglify-js", Version: "3.4.10", Locations: []types.Location{{StartLine: 13990, EndLine: 13996}}},
		{ID: "uglify-js@3.5.12", Name: "uglify-js", Version: "3.5.12", Locations: []types.Location{{StartLine: 13998, EndLine: 14004}}},
		{ID: "uid-number@0.0.6", Name: "uid-number", Version: "0.0.6", Locations: []types.Location{{StartLine: 14006, EndLine: 14009}}},
		{ID: "umask@1.1.0", Name: "umask", Version: "1.1.0", Locations: []types.Location{{StartLine: 14011, EndLine: 14014}}},
		{ID: "underscore@1.6.0", Name: "underscore", Version: "1.6.0", Locations: []types.Location{{StartLine: 14016, EndLine: 14019}}},
		{ID: "unicode-canonical-property-names-ecmascript@1.0.4", Name: "unicode-canonical-property-names-ecmascript", Version: "1.0.4", Locations: []types.Location{{StartLine: 14021, EndLine: 14024}}},
		{ID: "unicode-match-property-ecmascript@1.0.4", Name: "unicode-match-property-ecmascript", Version: "1.0.4", Locations: []types.Location{{StartLine: 14026, EndLine: 14032}}},
		{ID: "unicode-match-property-value-ecmascript@1.1.0", Name: "unicode-match-property-value-ecmascript", Version: "1.1.0", Locations: []types.Location{{StartLine: 14034, EndLine: 14037}}},
		{ID: "unicode-property-aliases-ecmascript@1.0.5", Name: "unicode-property-aliases-ecmascript", Version: "1.0.5", Locations: []types.Location{{StartLine: 14039, EndLine: 14042}}},
		{ID: "unified@7.1.0", Name: "unified", Version: "7.1.0", Locations: []types.Location{{StartLine: 14044, EndLine: 14056}}},
		{ID: "union-value@1.0.0", Name: "union-value", Version: "1.0.0", Locations: []types.Location{{StartLine: 14058, EndLine: 14066}}},
		{ID: "unique-filename@1.1.1", Name: "unique-filename", Version: "1.1.1", Locations: []types.Location{{StartLine: 14068, EndLine: 14073}}},
		{ID: "unique-slug@2.0.1", Name: "unique-slug", Version: "2.0.1", Locations: []types.Location{{StartLine: 14075, EndLine: 14080}}},
		{ID: "unique-string@1.0.0", Name: "unique-string", Version: "1.0.0", Locations: []types.Location{{StartLine: 14082, EndLine: 14087}}},
		{ID: "unist-util-stringify-position@1.1.2", Name: "unist-util-stringify-position", Version: "1.1.2", Locations: []types.Location{{StartLine: 14089, EndLine: 14092}}},
		{ID: "unist-util-stringify-position@2.0.0", Name: "unist-util-stringify-position", Version: "2.0.0", Locations: []types.Location{{StartLine: 14094, EndLine: 14099}}},
		{ID: "universal-user-agent@2.1.0", Name: "universal-user-agent", Version: "2.1.0", Locations: []types.Location{{StartLine: 14101, EndLine: 14106}}},
		{ID: "universalify@0.1.2", Name: "universalify", Version: "0.1.2", Locations: []types.Location{{StartLine: 14108, EndLine: 14111}}},
		{ID: "unpipe@1.0.0", Name: "unpipe", Version: "1.0.0", Locations: []types.Location{{StartLine: 14113, EndLine: 14116}}},
		{ID: "unquote@1.1.1", Name: "unquote", Version: "1.1.1", Locations: []types.Location{{StartLine: 14118, EndLine: 14121}}},
		{ID: "unset-value@1.0.0", Name: "unset-value", Version: "1.0.0", Locations: []types.Location{{StartLine: 14123, EndLine: 14129}}},
		{ID: "unzip-response@2.0.1", Name: "unzip-response", Version: "2.0.1", Locations: []types.Location{{StartLine: 14131, EndLine: 14134}}},
		{ID: "unzipper@0.8.14", Name: "unzipper", Version: "0.8.14", Locations: []types.Location{{StartLine: 14136, EndLine: 14149}}},
		{ID: "upath@1.1.2", Name: "upath", Version: "1.1.2", Locations: []types.Location{{StartLine: 14151, EndLine: 14154}}},
		{ID: "update-notifier@2.5.0", Name: "update-notifier", Version: "2.5.0", Locations: []types.Location{{StartLine: 14156, EndLine: 14170}}},
		{ID: "upper-case@1.1.3", Name: "upper-case", Version: "1.1.3", Locations: []types.Location{{StartLine: 14172, EndLine: 14175}}},
		{ID: "uri-js@4.2.2", Name: "uri-js", Version: "4.2.2", Locations: []types.Location{{StartLine: 14177, EndLine: 14182}}},
		{ID: "urix@0.1.0", Name: "urix", Version: "0.1.0", Locations: []types.Location{{StartLine: 14184, EndLine: 14187}}},
		{ID: "url-loader@1.1.2", Name: "url-loader", Version: "1.1.2", Locations: []types.Location{{StartLine: 14189, EndLine: 14196}}},
		{ID: "url-parse-lax@1.0.0", Name: "url-parse-lax", Version: "1.0.0", Locations: []types.Location{{StartLine: 14198, EndLine: 14203}}},
		{ID: "url-parse@1.4.7", Name: "url-parse", Version: "1.4.7", Locations: []types.Location{{StartLine: 14205, EndLine: 14211}}},
		{ID: "url-template@2.0.8", Name: "url-template", Version: "2.0.8", Locations: []types.Location{{StartLine: 14213, EndLine: 14216}}},
		{ID: "url-to-options@1.0.1", Name: "url-to-options", Version: "1.0.1", Locations: []types.Location{{StartLine: 14218, EndLine: 14221}}},
		{ID: "url@0.11.0", Name: "url", Version: "0.11.0", Locations: []types.Location{{StartLine: 14223, EndLine: 14229}}},
		{ID: "use@3.1.1", Name: "use", Version: "3.1.1", Locations: []types.Location{{StartLine: 14231, EndLine: 14234}}},
		{ID: "user-home@1.1.1", Name: "user-home", Version: "1.1.1", Locations: []types.Location{{StartLine: 14236, EndLine: 14239}}},
		{ID: "util-deprecate@1.0.2", Name: "util-deprecate", Version: "1.0.2", Locations: []types.Location{{StartLine: 14241, EndLine: 14244}}},
		{ID: "util-extend@1.0.3", Name: "util-extend", Version: "1.0.3", Locations: []types.Location{{StartLine: 14246, EndLine: 14249}}},
		{ID: "util.promisify@1.0.0", Name: "util.promisify", Version: "1.0.0", Locations: []types.Location{{StartLine: 14251, EndLine: 14257}}},
		{ID: "util@0.10.3", Name: "util", Version: "0.10.3", Locations: []types.Location{{StartLine: 14259, EndLine: 14264}}},
		{ID: "util@0.10.4", Name: "util", Version: "0.10.4", Locations: []types.Location{{StartLine: 14266, EndLine: 14271}}},
		{ID: "util@0.11.1", Name: "util", Version: "0.11.1", Locations: []types.Location{{StartLine: 14273, EndLine: 14278}}},
		{ID: "utila@0.4.0", Name: "utila", Version: "0.4.0", Locations: []types.Location{{StartLine: 14280, EndLine: 14283}}},
		{ID: "utils-merge@1.0.1", Name: "utils-merge", Version: "1.0.1", Locations: []types.Location{{StartLine: 14285, EndLine: 14288}}},
		{ID: "uuid@3.3.2", Name: "uuid", Version: "3.3.2", Locations: []types.Location{{StartLine: 14290, EndLine: 14293}}},
		{ID: "v8-compile-cache@2.0.3", Name: "v8-compile-cache", Version: "2.0.3", Locations: []types.Location{{StartLine: 14295, EndLine: 14298}}},
		{ID: "v8flags@2.1.1", Name: "v8flags", Version: "2.1.1", Locations: []types.Location{{StartLine: 14300, EndLine: 14305}}},
		{ID: "validate-npm-package-license@3.0.4", Name: "validate-npm-package-license", Version: "3.0.4", Locations: []types.Location{{StartLine: 14307, EndLine: 14313}}},
		{ID: "validate-npm-package-name@3.0.0", Name: "validate-npm-package-name", Version: "3.0.0", Locations: []types.Location{{StartLine: 14315, EndLine: 14320}}},
		{ID: "value-equal@0.4.0", Name: "value-equal", Version: "0.4.0", Locations: []types.Location{{StartLine: 14322, EndLine: 14325}}},
		{ID: "vary@1.1.2", Name: "vary", Version: "1.1.2", Locations: []types.Location{{StartLine: 14327, EndLine: 14330}}},
		{ID: "velocity-animate@1.5.2", Name: "velocity-animate", Version: "1.5.2", Locations: []types.Location{{StartLine: 14332, EndLine: 14335}}},
		{ID: "velocity-react@1.4.3", Name: "velocity-react", Version: "1.4.3", Locations: []types.Location{{StartLine: 14337, EndLine: 14345}}},
		{ID: "verror@1.10.0", Name: "verror", Version: "1.10.0", Locations: []types.Location{{StartLine: 14347, EndLine: 14354}}},
		{ID: "vfile-message@1.1.1", Name: "vfile-message", Version: "1.1.1", Locations: []types.Location{{StartLine: 14356, EndLine: 14361}}},
		{ID: "vfile-message@2.0.0", Name: "vfile-message", Version: "2.0.0", Locations: []types.Location{{StartLine: 14363, EndLine: 14369}}},
		{ID: "vfile@3.0.1", Name: "vfile", Version: "3.0.1", Locations: []types.Location{{StartLine: 14371, EndLine: 14379}}},
		{ID: "vfile@4.0.0", Name: "vfile", Version: "4.0.0", Locations: []types.Location{{StartLine: 14381, EndLine: 14390}}},
		{ID: "vm-browserify@0.0.4", Name: "vm-browserify", Version: "0.0.4", Locations: []types.Location{{StartLine: 14392, EndLine: 14397}}},
		{ID: "w3c-hr-time@1.0.1", Name: "w3c-hr-time", Version: "1.0.1", Locations: []types.Location{{StartLine: 14399, EndLine: 14404}}},
		{ID: "walker@1.0.7", Name: "walker", Version: "1.0.7", Locations: []types.Location{{StartLine: 14406, EndLine: 14411}}},
		{ID: "warning@3.0.0", Name: "warning", Version: "3.0.0", Locations: []types.Location{{StartLine: 14413, EndLine: 14418}}},
		{ID: "warning@4.0.3", Name: "warning", Version: "4.0.3", Locations: []types.Location{{StartLine: 14420, EndLine: 14425}}},
		{ID: "watch@0.18.0", Name: "watch", Version: "0.18.0", Locations: []types.Location{{StartLine: 14427, EndLine: 14433}}},
		{ID: "watchpack@1.6.0", Name: "watchpack", Version: "1.6.0", Locations: []types.Location{{StartLine: 14435, EndLine: 14442}}},
		{ID: "wbuf@1.7.3", Name: "wbuf", Version: "1.7.3", Locations: []types.Location{{StartLine: 14444, EndLine: 14449}}},
		{ID: "wcwidth@1.0.1", Name: "wcwidth", Version: "1.0.1", Locations: []types.Location{{StartLine: 14451, EndLine: 14456}}},
		{ID: "web-namespaces@1.1.3", Name: "web-namespaces", Version: "1.1.3", Locations: []types.Location{{StartLine: 14458, EndLine: 14461}}},
		{ID: "webidl-conversions@4.0.2", Name: "webidl-conversions", Version: "4.0.2", Locations: []types.Location{{StartLine: 14463, EndLine: 14466}}},
		{ID: "webpack-bundle-analyzer@3.3.2", Name: "webpack-bundle-analyzer", Version: "3.3.2", Locations: []types.Location{{StartLine: 14468, EndLine: 14485}}},
		{ID: "webpack-cli@3.3.2", Name: "webpack-cli", Version: "3.3.2", Locations: []types.Location{{StartLine: 14487, EndLine: 14502}}},
		{ID: "webpack-dev-middleware@3.7.0", Name: "webpack-dev-middleware", Version: "3.7.0", Locations: []types.Location{{StartLine: 14504, EndLine: 14512}}},
		{ID: "webpack-dev-server@3.3.1", Name: "webpack-dev-server", Version: "3.3.1", Locations: []types.Location{{StartLine: 14514, EndLine: 14548}}},
		{ID: "webpack-hot-middleware@2.25.0", Name: "webpack-hot-middleware", Version: "2.25.0", Locations: []types.Location{{StartLine: 14550, EndLine: 14558}}},
		{ID: "webpack-log@2.0.0", Name: "webpack-log", Version: "2.0.0", Locations: []types.Location{{StartLine: 14560, EndLine: 14566}}},
		{ID: "webpack-merge@4.2.1", Name: "webpack-merge", Version: "4.2.1", Locations: []types.Location{{StartLine: 14568, EndLine: 14573}}},
		{ID: "webpack-sources@1.3.0", Name: "webpack-sources", Version: "1.3.0", Locations: []types.Location{{StartLine: 14575, EndLine: 14581}}},
		{ID: "webpack@4.31.0", Name: "webpack", Version: "4.31.0", Locations: []types.Location{{StartLine: 14583, EndLine: 14611}}},
		{ID: "websocket-driver@0.7.0", Name: "websocket-driver", Version: "0.7.0", Locations: []types.Location{{StartLine: 14613, EndLine: 14619}}},
		{ID: "websocket-extensions@0.1.3", Name: "websocket-extensions", Version: "0.1.3", Locations: []types.Location{{StartLine: 14621, EndLine: 14624}}},
		{ID: "whatwg-encoding@1.0.5", Name: "whatwg-encoding", Version: "1.0.5", Locations: []types.Location{{StartLine: 14626, EndLine: 14631}}},
		{ID: "whatwg-fetch@3.0.0", Name: "whatwg-fetch", Version: "3.0.0", Locations: []types.Location{{StartLine: 14633, EndLine: 14636}}},
		{ID: "whatwg-mimetype@2.3.0", Name: "whatwg-mimetype", Version: "2.3.0", Locations: []types.Location{{StartLine: 14638, EndLine: 14641}}},
		{ID: "whatwg-url@6.5.0", Name: "whatwg-url", Version: "6.5.0", Locations: []types.Location{{StartLine: 14643, EndLine: 14650}}},
		{ID: "whatwg-url@7.0.0", Name: "whatwg-url", Version: "7.0.0", Locations: []types.Location{{StartLine: 14652, EndLine: 14659}}},
		{ID: "which-module@1.0.0", Name: "which-module", Version: "1.0.0", Locations: []types.Location{{StartLine: 14661, EndLine: 14664}}},
		{ID: "which-module@2.0.0", Name: "which-module", Version: "2.0.0", Locations: []types.Location{{StartLine: 14666, EndLine: 14669}}},
		{ID: "which@1.3.1", Name: "which", Version: "1.3.1", Locations: []types.Location{{StartLine: 14671, EndLine: 14676}}},
		{ID: "wide-align@1.1.3", Name: "wide-align", Version: "1.1.3", Locations: []types.Location{{StartLine: 14678, EndLine: 14683}}},
		{ID: "widest-line@2.0.1", Name: "widest-line", Version: "2.0.1", Locations: []types.Location{{StartLine: 14685, EndLine: 14690}}},
		{ID: "window-size@0.2.0", Name: "window-size", Version: "0.2.0", Locations: []types.Location{{StartLine: 14692, EndLine: 14695}}},
		{ID: "windows-release@3.2.0", Name: "windows-release", Version: "3.2.0", Locations: []types.Location{{StartLine: 14697, EndLine: 14702}}},
		{ID: "wordwrap@0.0.3", Name: "wordwrap", Version: "0.0.3", Locations: []types.Location{{StartLine: 14704, EndLine: 14707}}},
		{ID: "wordwrap@1.0.0", Name: "wordwrap", Version: "1.0.0", Locations: []types.Location{{StartLine: 14709, EndLine: 14712}}},
		{ID: "worker-farm@1.7.0", Name: "worker-farm", Version: "1.7.0", Locations: []types.Location{{StartLine: 14714, EndLine: 14719}}},
		{ID: "wrap-ansi@2.1.0", Name: "wrap-ansi", Version: "2.1.0", Locations: []types.Location{{StartLine: 14721, EndLine: 14727}}},
		{ID: "wrap-ansi@3.0.1", Name: "wrap-ansi", Version: "3.0.1", Locations: []types.Location{{StartLine: 14729, EndLine: 14735}}},
		{ID: "wrappy@1.0.2", Name: "wrappy", Version: "1.0.2", Locations: []types.Location{{StartLine: 14737, EndLine: 14740}}},
		{ID: "write-file-atomic@1.3.4", Name: "write-file-atomic", Version: "1.3.4", Locations: []types.Location{{StartLine: 14742, EndLine: 14749}}},
		{ID: "write-file-atomic@2.4.2", Name: "write-file-atomic", Version: "2.4.2", Locations: []types.Location{{StartLine: 14751, EndLine: 14758}}},
		{ID: "write-json-file@2.3.0", Name: "write-json-file", Version: "2.3.0", Locations: []types.Location{{StartLine: 14760, EndLine: 14770}}},
		{ID: "write@1.0.3", Name: "write", Version: "1.0.3", Locations: []types.Location{{StartLine: 14772, EndLine: 14777}}},
		{ID: "ws@5.2.2", Name: "ws", Version: "5.2.2", Locations: []types.Location{{StartLine: 14779, EndLine: 14784}}},
		{ID: "ws@6.2.1", Name: "ws", Version: "6.2.1", Locations: []types.Location{{StartLine: 14786, EndLine: 14791}}},
		{ID: "ws@6.1.4", Name: "ws", Version: "6.1.4", Locations: []types.Location{{StartLine: 14793, EndLine: 14798}}},
		{ID: "x-is-string@0.1.0", Name: "x-is-string", Version: "0.1.0", Locations: []types.Location{{StartLine: 14800, EndLine: 14803}}},
		{ID: "xdg-basedir@3.0.0", Name: "xdg-basedir", Version: "3.0.0", Locations: []types.Location{{StartLine: 14805, EndLine: 14808}}},
		{ID: "xml-name-validator@3.0.0", Name: "xml-name-validator", Version: "3.0.0", Locations: []types.Location{{StartLine: 14810, EndLine: 14813}}},
		{ID: "xmlhttprequest-ssl@1.5.5", Name: "xmlhttprequest-ssl", Version: "1.5.5", Locations: []types.Location{{StartLine: 14815, EndLine: 14818}}},
		{ID: "xtend@4.0.1", Name: "xtend", Version: "4.0.1", Locations: []types.Location{{StartLine: 14820, EndLine: 14823}}},
		{ID: "y18n@3.2.1", Name: "y18n", Version: "3.2.1", Locations: []types.Location{{StartLine: 14825, EndLine: 14828}}},
		{ID: "y18n@4.0.0", Name: "y18n", Version: "4.0.0", Locations: []types.Location{{StartLine: 14830, EndLine: 14833}}},
		{ID: "yallist@2.1.2", Name: "yallist", Version: "2.1.2", Locations: []types.Location{{StartLine: 14835, EndLine: 14838}}},
		{ID: "yallist@3.0.3", Name: "yallist", Version: "3.0.3", Locations: []types.Location{{StartLine: 14840, EndLine: 14843}}},
		{ID: "yargs-parser@11.1.1", Name: "yargs-parser", Version: "11.1.1", Locations: []types.Location{{StartLine: 14845, EndLine: 14851}}},
		{ID: "yargs-parser@2.4.1", Name: "yargs-parser", Version: "2.4.1", Locations: []types.Location{{StartLine: 14853, EndLine: 14859}}},
		{ID: "yargs-parser@9.0.2", Name: "yargs-parser", Version: "9.0.2", Locations: []types.Location{{StartLine: 14861, EndLine: 14866}}},
		{ID: "yargs@12.0.5", Name: "yargs", Version: "12.0.5", Locations: []types.Location{{StartLine: 14868, EndLine: 14884}}},
		{ID: "yargs@11.1.0", Name: "yargs", Version: "11.1.0", Locations: []types.Location{{StartLine: 14886, EndLine: 14902}}},
		{ID: "yargs@4.8.1", Name: "yargs", Version: "4.8.1", Locations: []types.Location{{StartLine: 14904, EndLine: 14922}}},
		{ID: "yeast@0.1.2", Name: "yeast", Version: "0.1.2", Locations: []types.Location{{StartLine: 14924, EndLine: 14927}}},
	}

	// ... and
	// node test_deps_generator/index.js yarn.lock
	yarnRealWorldDeps = []types.Dependency{
		{
			ID: "@babel/code-frame@7.0.0",
			DependsOn: []string{
				"@babel/highlight@7.0.0",
			},
		},
		{
			ID: "@babel/code-frame@7.0.0-beta.44",
			DependsOn: []string{
				"@babel/highlight@7.0.0-beta.44",
			},
		},
		{
			ID: "@babel/core@7.1.0",
			DependsOn: []string{
				"@babel/code-frame@7.0.0",
				"@babel/generator@7.4.4",
				"@babel/helpers@7.4.4",
				"@babel/parser@7.4.4",
				"@babel/template@7.4.4",
				"@babel/traverse@7.4.4",
				"@babel/types@7.4.4",
				"convert-source-map@1.6.0",
				"debug@3.2.6",
				"json5@0.5.1",
				"lodash@4.17.11",
				"resolve@1.10.1",
				"semver@5.7.0",
				"source-map@0.5.7",
			},
		},
		{
			ID: "@babel/core@7.4.4",
			DependsOn: []string{
				"@babel/code-frame@7.0.0",
				"@babel/generator@7.4.4",
				"@babel/helpers@7.4.4",
				"@babel/parser@7.4.4",
				"@babel/template@7.4.4",
				"@babel/traverse@7.4.4",
				"@babel/types@7.4.4",
				"convert-source-map@1.6.0",
				"debug@4.1.1",
				"json5@2.1.0",
				"lodash@4.17.11",
				"resolve@1.10.1",
				"semver@5.7.0",
				"source-map@0.5.7",
			},
		},
		{
			ID: "@babel/generator@7.0.0-beta.44",
			DependsOn: []string{
				"@babel/types@7.0.0-beta.44",
				"jsesc@2.5.2",
				"lodash@4.17.11",
				"source-map@0.5.7",
				"trim-right@1.0.1",
			},
		},
		{
			ID: "@babel/generator@7.4.4",
			DependsOn: []string{
				"@babel/types@7.4.4",
				"jsesc@2.5.2",
				"lodash@4.17.11",
				"source-map@0.5.7",
				"trim-right@1.0.1",
			},
		},
		{
			ID: "@babel/helper-annotate-as-pure@7.0.0",
			DependsOn: []string{
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-builder-binary-assignment-operator-visitor@7.1.0",
			DependsOn: []string{
				"@babel/helper-explode-assignable-expression@7.1.0",
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-builder-react-jsx@7.3.0",
			DependsOn: []string{
				"@babel/types@7.4.4",
				"esutils@2.0.2",
			},
		},
		{
			ID: "@babel/helper-call-delegate@7.4.4",
			DependsOn: []string{
				"@babel/helper-hoist-variables@7.4.4",
				"@babel/traverse@7.4.4",
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-create-class-features-plugin@7.4.4",
			DependsOn: []string{
				"@babel/helper-function-name@7.1.0",
				"@babel/helper-member-expression-to-functions@7.0.0",
				"@babel/helper-optimise-call-expression@7.0.0",
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-replace-supers@7.4.4",
				"@babel/helper-split-export-declaration@7.4.4",
			},
		},
		{
			ID: "@babel/helper-define-map@7.4.4",
			DependsOn: []string{
				"@babel/helper-function-name@7.1.0",
				"@babel/types@7.4.4",
				"lodash@4.17.11",
			},
		},
		{
			ID: "@babel/helper-explode-assignable-expression@7.1.0",
			DependsOn: []string{
				"@babel/traverse@7.4.4",
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-function-name@7.0.0-beta.44",
			DependsOn: []string{
				"@babel/helper-get-function-arity@7.0.0-beta.44",
				"@babel/template@7.0.0-beta.44",
				"@babel/types@7.0.0-beta.44",
			},
		},
		{
			ID: "@babel/helper-function-name@7.1.0",
			DependsOn: []string{
				"@babel/helper-get-function-arity@7.0.0",
				"@babel/template@7.4.4",
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-get-function-arity@7.0.0-beta.44",
			DependsOn: []string{
				"@babel/types@7.0.0-beta.44",
			},
		},
		{
			ID: "@babel/helper-get-function-arity@7.0.0",
			DependsOn: []string{
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-hoist-variables@7.4.4",
			DependsOn: []string{
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-member-expression-to-functions@7.0.0",
			DependsOn: []string{
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-module-imports@7.0.0",
			DependsOn: []string{
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-module-transforms@7.4.4",
			DependsOn: []string{
				"@babel/helper-module-imports@7.0.0",
				"@babel/helper-simple-access@7.1.0",
				"@babel/helper-split-export-declaration@7.4.4",
				"@babel/template@7.4.4",
				"@babel/types@7.4.4",
				"lodash@4.17.11",
			},
		},
		{
			ID: "@babel/helper-optimise-call-expression@7.0.0",
			DependsOn: []string{
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-regex@7.4.4",
			DependsOn: []string{
				"lodash@4.17.11",
			},
		},
		{
			ID: "@babel/helper-remap-async-to-generator@7.1.0",
			DependsOn: []string{
				"@babel/helper-annotate-as-pure@7.0.0",
				"@babel/helper-wrap-function@7.2.0",
				"@babel/template@7.4.4",
				"@babel/traverse@7.4.4",
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-replace-supers@7.4.4",
			DependsOn: []string{
				"@babel/helper-member-expression-to-functions@7.0.0",
				"@babel/helper-optimise-call-expression@7.0.0",
				"@babel/traverse@7.4.4",
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-simple-access@7.1.0",
			DependsOn: []string{
				"@babel/template@7.4.4",
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-split-export-declaration@7.0.0-beta.44",
			DependsOn: []string{
				"@babel/types@7.0.0-beta.44",
			},
		},
		{
			ID: "@babel/helper-split-export-declaration@7.4.4",
			DependsOn: []string{
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helper-wrap-function@7.2.0",
			DependsOn: []string{
				"@babel/helper-function-name@7.1.0",
				"@babel/template@7.4.4",
				"@babel/traverse@7.4.4",
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/helpers@7.4.4",
			DependsOn: []string{
				"@babel/template@7.4.4",
				"@babel/traverse@7.4.4",
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/highlight@7.0.0-beta.44",
			DependsOn: []string{
				"chalk@2.4.2",
				"esutils@2.0.2",
				"js-tokens@3.0.2",
			},
		},
		{
			ID: "@babel/highlight@7.0.0",
			DependsOn: []string{
				"chalk@2.4.2",
				"esutils@2.0.2",
				"js-tokens@4.0.0",
			},
		},
		{
			ID: "@babel/plugin-proposal-async-generator-functions@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-remap-async-to-generator@7.1.0",
				"@babel/plugin-syntax-async-generators@7.2.0",
			},
		},
		{
			ID: "@babel/plugin-proposal-class-properties@7.1.0",
			DependsOn: []string{
				"@babel/helper-function-name@7.1.0",
				"@babel/helper-member-expression-to-functions@7.0.0",
				"@babel/helper-optimise-call-expression@7.0.0",
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-replace-supers@7.4.4",
				"@babel/plugin-syntax-class-properties@7.2.0",
			},
		},
		{
			ID: "@babel/plugin-proposal-class-properties@7.4.4",
			DependsOn: []string{
				"@babel/helper-create-class-features-plugin@7.4.4",
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-proposal-decorators@7.1.2",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-replace-supers@7.4.4",
				"@babel/helper-split-export-declaration@7.4.4",
				"@babel/plugin-syntax-decorators@7.2.0",
			},
		},
		{
			ID: "@babel/plugin-proposal-json-strings@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-syntax-json-strings@7.2.0",
			},
		},
		{
			ID: "@babel/plugin-proposal-object-rest-spread@7.0.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-syntax-object-rest-spread@7.2.0",
			},
		},
		{
			ID: "@babel/plugin-proposal-object-rest-spread@7.4.4",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-syntax-object-rest-spread@7.2.0",
			},
		},
		{
			ID: "@babel/plugin-proposal-optional-catch-binding@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-syntax-optional-catch-binding@7.2.0",
			},
		},
		{
			ID: "@babel/plugin-proposal-unicode-property-regex@7.4.4",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-regex@7.4.4",
				"regexpu-core@4.5.4",
			},
		},
		{
			ID: "@babel/plugin-syntax-async-generators@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-syntax-class-properties@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-syntax-decorators@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-syntax-dynamic-import@7.0.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-syntax-dynamic-import@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-syntax-flow@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-syntax-json-strings@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-syntax-jsx@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-syntax-object-rest-spread@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-syntax-optional-catch-binding@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-syntax-typescript@7.3.3",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-arrow-functions@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-async-to-generator@7.4.4",
			DependsOn: []string{
				"@babel/helper-module-imports@7.0.0",
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-remap-async-to-generator@7.1.0",
			},
		},
		{
			ID: "@babel/plugin-transform-block-scoped-functions@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-block-scoping@7.4.4",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"lodash@4.17.11",
			},
		},
		{
			ID: "@babel/plugin-transform-classes@7.1.0",
			DependsOn: []string{
				"@babel/helper-annotate-as-pure@7.0.0",
				"@babel/helper-define-map@7.4.4",
				"@babel/helper-function-name@7.1.0",
				"@babel/helper-optimise-call-expression@7.0.0",
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-replace-supers@7.4.4",
				"@babel/helper-split-export-declaration@7.4.4",
				"globals@11.12.0",
			},
		},
		{
			ID: "@babel/plugin-transform-classes@7.4.4",
			DependsOn: []string{
				"@babel/helper-annotate-as-pure@7.0.0",
				"@babel/helper-define-map@7.4.4",
				"@babel/helper-function-name@7.1.0",
				"@babel/helper-optimise-call-expression@7.0.0",
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-replace-supers@7.4.4",
				"@babel/helper-split-export-declaration@7.4.4",
				"globals@11.12.0",
			},
		},
		{
			ID: "@babel/plugin-transform-computed-properties@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-destructuring@7.0.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-destructuring@7.4.4",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-dotall-regex@7.4.4",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-regex@7.4.4",
				"regexpu-core@4.5.4",
			},
		},
		{
			ID: "@babel/plugin-transform-duplicate-keys@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-exponentiation-operator@7.2.0",
			DependsOn: []string{
				"@babel/helper-builder-binary-assignment-operator-visitor@7.1.0",
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-flow-strip-types@7.0.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-syntax-flow@7.2.0",
			},
		},
		{
			ID: "@babel/plugin-transform-flow-strip-types@7.4.4",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-syntax-flow@7.2.0",
			},
		},
		{
			ID: "@babel/plugin-transform-for-of@7.4.4",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-function-name@7.4.4",
			DependsOn: []string{
				"@babel/helper-function-name@7.1.0",
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-literals@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-member-expression-literals@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-modules-amd@7.2.0",
			DependsOn: []string{
				"@babel/helper-module-transforms@7.4.4",
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-modules-commonjs@7.4.4",
			DependsOn: []string{
				"@babel/helper-module-transforms@7.4.4",
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-simple-access@7.1.0",
			},
		},
		{
			ID: "@babel/plugin-transform-modules-systemjs@7.4.4",
			DependsOn: []string{
				"@babel/helper-hoist-variables@7.4.4",
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-modules-umd@7.2.0",
			DependsOn: []string{
				"@babel/helper-module-transforms@7.4.4",
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-named-capturing-groups-regex@7.4.4",
			DependsOn: []string{
				"regexp-tree@0.1.6",
			},
		},
		{
			ID: "@babel/plugin-transform-new-target@7.4.4",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-object-super@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-replace-supers@7.4.4",
			},
		},
		{
			ID: "@babel/plugin-transform-parameters@7.4.4",
			DependsOn: []string{
				"@babel/helper-call-delegate@7.4.4",
				"@babel/helper-get-function-arity@7.0.0",
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-property-literals@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-react-constant-elements@7.0.0",
			DependsOn: []string{
				"@babel/helper-annotate-as-pure@7.0.0",
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-react-constant-elements@7.2.0",
			DependsOn: []string{
				"@babel/helper-annotate-as-pure@7.0.0",
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-react-display-name@7.0.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-react-display-name@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-react-jsx-self@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-syntax-jsx@7.2.0",
			},
		},
		{
			ID: "@babel/plugin-transform-react-jsx-source@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-syntax-jsx@7.2.0",
			},
		},
		{
			ID: "@babel/plugin-transform-react-jsx@7.3.0",
			DependsOn: []string{
				"@babel/helper-builder-react-jsx@7.3.0",
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-syntax-jsx@7.2.0",
			},
		},
		{
			ID: "@babel/plugin-transform-regenerator@7.4.4",
			DependsOn: []string{
				"regenerator-transform@0.13.4",
			},
		},
		{
			ID: "@babel/plugin-transform-reserved-words@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-runtime@7.1.0",
			DependsOn: []string{
				"@babel/helper-module-imports@7.0.0",
				"@babel/helper-plugin-utils@7.0.0",
				"resolve@1.10.1",
				"semver@5.7.0",
			},
		},
		{
			ID: "@babel/plugin-transform-shorthand-properties@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-spread@7.2.2",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-sticky-regex@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-regex@7.4.4",
			},
		},
		{
			ID: "@babel/plugin-transform-template-literals@7.4.4",
			DependsOn: []string{
				"@babel/helper-annotate-as-pure@7.0.0",
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-typeof-symbol@7.2.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
			},
		},
		{
			ID: "@babel/plugin-transform-typescript@7.4.4",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-syntax-typescript@7.3.3",
			},
		},
		{
			ID: "@babel/plugin-transform-unicode-regex@7.4.4",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/helper-regex@7.4.4",
				"regexpu-core@4.5.4",
			},
		},
		{
			ID: "@babel/preset-env@7.1.0",
			DependsOn: []string{
				"@babel/helper-module-imports@7.0.0",
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-proposal-async-generator-functions@7.2.0",
				"@babel/plugin-proposal-json-strings@7.2.0",
				"@babel/plugin-proposal-object-rest-spread@7.4.4",
				"@babel/plugin-proposal-optional-catch-binding@7.2.0",
				"@babel/plugin-proposal-unicode-property-regex@7.4.4",
				"@babel/plugin-syntax-async-generators@7.2.0",
				"@babel/plugin-syntax-object-rest-spread@7.2.0",
				"@babel/plugin-syntax-optional-catch-binding@7.2.0",
				"@babel/plugin-transform-arrow-functions@7.2.0",
				"@babel/plugin-transform-async-to-generator@7.4.4",
				"@babel/plugin-transform-block-scoped-functions@7.2.0",
				"@babel/plugin-transform-block-scoping@7.4.4",
				"@babel/plugin-transform-classes@7.4.4",
				"@babel/plugin-transform-computed-properties@7.2.0",
				"@babel/plugin-transform-destructuring@7.4.4",
				"@babel/plugin-transform-dotall-regex@7.4.4",
				"@babel/plugin-transform-duplicate-keys@7.2.0",
				"@babel/plugin-transform-exponentiation-operator@7.2.0",
				"@babel/plugin-transform-for-of@7.4.4",
				"@babel/plugin-transform-function-name@7.4.4",
				"@babel/plugin-transform-literals@7.2.0",
				"@babel/plugin-transform-modules-amd@7.2.0",
				"@babel/plugin-transform-modules-commonjs@7.4.4",
				"@babel/plugin-transform-modules-systemjs@7.4.4",
				"@babel/plugin-transform-modules-umd@7.2.0",
				"@babel/plugin-transform-new-target@7.4.4",
				"@babel/plugin-transform-object-super@7.2.0",
				"@babel/plugin-transform-parameters@7.4.4",
				"@babel/plugin-transform-regenerator@7.4.4",
				"@babel/plugin-transform-shorthand-properties@7.2.0",
				"@babel/plugin-transform-spread@7.2.2",
				"@babel/plugin-transform-sticky-regex@7.2.0",
				"@babel/plugin-transform-template-literals@7.4.4",
				"@babel/plugin-transform-typeof-symbol@7.2.0",
				"@babel/plugin-transform-unicode-regex@7.4.4",
				"browserslist@4.6.0",
				"invariant@2.2.4",
				"js-levenshtein@1.1.6",
				"semver@5.7.0",
			},
		},
		{
			ID: "@babel/preset-env@7.4.4",
			DependsOn: []string{
				"@babel/helper-module-imports@7.0.0",
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-proposal-async-generator-functions@7.2.0",
				"@babel/plugin-proposal-json-strings@7.2.0",
				"@babel/plugin-proposal-object-rest-spread@7.4.4",
				"@babel/plugin-proposal-optional-catch-binding@7.2.0",
				"@babel/plugin-proposal-unicode-property-regex@7.4.4",
				"@babel/plugin-syntax-async-generators@7.2.0",
				"@babel/plugin-syntax-json-strings@7.2.0",
				"@babel/plugin-syntax-object-rest-spread@7.2.0",
				"@babel/plugin-syntax-optional-catch-binding@7.2.0",
				"@babel/plugin-transform-arrow-functions@7.2.0",
				"@babel/plugin-transform-async-to-generator@7.4.4",
				"@babel/plugin-transform-block-scoped-functions@7.2.0",
				"@babel/plugin-transform-block-scoping@7.4.4",
				"@babel/plugin-transform-classes@7.4.4",
				"@babel/plugin-transform-computed-properties@7.2.0",
				"@babel/plugin-transform-destructuring@7.4.4",
				"@babel/plugin-transform-dotall-regex@7.4.4",
				"@babel/plugin-transform-duplicate-keys@7.2.0",
				"@babel/plugin-transform-exponentiation-operator@7.2.0",
				"@babel/plugin-transform-for-of@7.4.4",
				"@babel/plugin-transform-function-name@7.4.4",
				"@babel/plugin-transform-literals@7.2.0",
				"@babel/plugin-transform-member-expression-literals@7.2.0",
				"@babel/plugin-transform-modules-amd@7.2.0",
				"@babel/plugin-transform-modules-commonjs@7.4.4",
				"@babel/plugin-transform-modules-systemjs@7.4.4",
				"@babel/plugin-transform-modules-umd@7.2.0",
				"@babel/plugin-transform-named-capturing-groups-regex@7.4.4",
				"@babel/plugin-transform-new-target@7.4.4",
				"@babel/plugin-transform-object-super@7.2.0",
				"@babel/plugin-transform-parameters@7.4.4",
				"@babel/plugin-transform-property-literals@7.2.0",
				"@babel/plugin-transform-regenerator@7.4.4",
				"@babel/plugin-transform-reserved-words@7.2.0",
				"@babel/plugin-transform-shorthand-properties@7.2.0",
				"@babel/plugin-transform-spread@7.2.2",
				"@babel/plugin-transform-sticky-regex@7.2.0",
				"@babel/plugin-transform-template-literals@7.4.4",
				"@babel/plugin-transform-typeof-symbol@7.2.0",
				"@babel/plugin-transform-unicode-regex@7.4.4",
				"@babel/types@7.4.4",
				"browserslist@4.6.0",
				"core-js-compat@3.0.1",
				"invariant@2.2.4",
				"js-levenshtein@1.1.6",
				"semver@5.7.0",
			},
		},
		{
			ID: "@babel/preset-flow@7.0.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-transform-flow-strip-types@7.4.4",
			},
		},
		{
			ID: "@babel/preset-react@7.0.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-transform-react-display-name@7.2.0",
				"@babel/plugin-transform-react-jsx@7.3.0",
				"@babel/plugin-transform-react-jsx-self@7.2.0",
				"@babel/plugin-transform-react-jsx-source@7.2.0",
			},
		},
		{
			ID: "@babel/preset-typescript@7.1.0",
			DependsOn: []string{
				"@babel/helper-plugin-utils@7.0.0",
				"@babel/plugin-transform-typescript@7.4.4",
			},
		},
		{
			ID: "@babel/register@7.4.4",
			DependsOn: []string{
				"core-js@3.0.1",
				"find-cache-dir@2.1.0",
				"lodash@4.17.11",
				"mkdirp@0.5.1",
				"pirates@4.0.1",
				"source-map-support@0.5.12",
			},
		},
		{
			ID: "@babel/runtime@7.0.0",
			DependsOn: []string{
				"regenerator-runtime@0.12.1",
			},
		},
		{
			ID: "@babel/runtime@7.4.4",
			DependsOn: []string{
				"regenerator-runtime@0.13.2",
			},
		},
		{
			ID: "@babel/template@7.0.0-beta.44",
			DependsOn: []string{
				"@babel/code-frame@7.0.0-beta.44",
				"@babel/types@7.0.0-beta.44",
				"babylon@7.0.0-beta.44",
				"lodash@4.17.11",
			},
		},
		{
			ID: "@babel/template@7.4.4",
			DependsOn: []string{
				"@babel/code-frame@7.0.0",
				"@babel/parser@7.4.4",
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@babel/traverse@7.0.0-beta.44",
			DependsOn: []string{
				"@babel/code-frame@7.0.0-beta.44",
				"@babel/generator@7.0.0-beta.44",
				"@babel/helper-function-name@7.0.0-beta.44",
				"@babel/helper-split-export-declaration@7.0.0-beta.44",
				"@babel/types@7.0.0-beta.44",
				"babylon@7.0.0-beta.44",
				"debug@3.2.6",
				"globals@11.12.0",
				"invariant@2.2.4",
				"lodash@4.17.11",
			},
		},
		{
			ID: "@babel/traverse@7.4.4",
			DependsOn: []string{
				"@babel/code-frame@7.0.0",
				"@babel/generator@7.4.4",
				"@babel/helper-function-name@7.1.0",
				"@babel/helper-split-export-declaration@7.4.4",
				"@babel/parser@7.4.4",
				"@babel/types@7.4.4",
				"debug@4.1.1",
				"globals@11.12.0",
				"lodash@4.17.11",
			},
		},
		{
			ID: "@babel/types@7.0.0-beta.44",
			DependsOn: []string{
				"esutils@2.0.2",
				"lodash@4.17.11",
				"to-fast-properties@2.0.0",
			},
		},
		{
			ID: "@babel/types@7.4.4",
			DependsOn: []string{
				"esutils@2.0.2",
				"lodash@4.17.11",
				"to-fast-properties@2.0.0",
			},
		},
		{
			ID: "@emotion/cache@0.8.8",
			DependsOn: []string{
				"@emotion/sheet@0.8.1",
				"@emotion/stylis@0.7.1",
				"@emotion/utils@0.8.2",
			},
		},
		{
			ID: "@emotion/core@0.13.1",
			DependsOn: []string{
				"@emotion/cache@0.8.8",
				"@emotion/css@0.9.8",
				"@emotion/serialize@0.9.1",
				"@emotion/sheet@0.8.1",
				"@emotion/utils@0.8.2",
			},
		},
		{
			ID: "@emotion/css@0.9.8",
			DependsOn: []string{
				"@emotion/serialize@0.9.1",
				"@emotion/utils@0.8.2",
			},
		},
		{
			ID: "@emotion/is-prop-valid@0.6.8",
			DependsOn: []string{
				"@emotion/memoize@0.6.6",
			},
		},
		{
			ID: "@emotion/is-prop-valid@0.7.3",
			DependsOn: []string{
				"@emotion/memoize@0.7.1",
			},
		},
		{
			ID: "@emotion/provider@0.11.2",
			DependsOn: []string{
				"@emotion/cache@0.8.8",
				"@emotion/weak-memoize@0.1.3",
			},
		},
		{
			ID: "@emotion/serialize@0.9.1",
			DependsOn: []string{
				"@emotion/hash@0.6.6",
				"@emotion/memoize@0.6.6",
				"@emotion/unitless@0.6.7",
				"@emotion/utils@0.8.2",
			},
		},
		{
			ID: "@emotion/styled-base@0.10.6",
			DependsOn: []string{
				"@emotion/is-prop-valid@0.6.8",
				"@emotion/serialize@0.9.1",
				"@emotion/utils@0.8.2",
			},
		},
		{
			ID: "@emotion/styled@0.10.6",
			DependsOn: []string{
				"@emotion/styled-base@0.10.6",
			},
		},
		{
			ID: "@loadable/component@5.10.1",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"hoist-non-react-statics@3.3.0",
			},
		},
		{
			ID: "@material-ui/core@3.9.3",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"@material-ui/system@3.0.0-alpha.2",
				"@material-ui/utils@3.0.0-alpha.3",
				"@types/jss@9.5.8",
				"@types/react-transition-group@2.9.1",
				"brcast@3.0.1",
				"classnames@2.2.6",
				"csstype@2.6.4",
				"debounce@1.2.0",
				"deepmerge@3.2.0",
				"dom-helpers@3.4.0",
				"hoist-non-react-statics@3.3.0",
				"is-plain-object@2.0.4",
				"jss@9.8.7",
				"jss-camel-case@6.1.0",
				"jss-default-unit@8.0.2",
				"jss-global@3.0.0",
				"jss-nested@6.0.1",
				"jss-props-sort@6.0.0",
				"jss-vendor-prefixer@7.0.0",
				"normalize-scroll-left@0.1.2",
				"popper.js@1.15.0",
				"prop-types@15.7.2",
				"react-event-listener@0.6.6",
				"react-transition-group@2.9.0",
				"recompose@0.30.0",
				"warning@4.0.3",
			},
		},
		{
			ID: "@material-ui/icons@3.0.2",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"recompose@0.30.0",
			},
		},
		{
			ID: "@material-ui/system@3.0.0-alpha.2",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"deepmerge@3.2.0",
				"prop-types@15.7.2",
				"warning@4.0.3",
			},
		},
		{
			ID: "@material-ui/utils@3.0.0-alpha.3",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"prop-types@15.7.2",
				"react-is@16.8.6",
			},
		},
		{
			ID: "@mrmlnc/readdir-enhanced@2.2.1",
			DependsOn: []string{
				"call-me-maybe@1.0.1",
				"glob-to-regexp@0.3.0",
			},
		},
		{
			ID: "@octokit/rest@15.18.1",
			DependsOn: []string{
				"before-after-hook@1.4.0",
				"btoa-lite@1.0.0",
				"debug@3.2.6",
				"http-proxy-agent@2.1.0",
				"https-proxy-agent@2.2.1",
				"lodash@4.17.11",
				"node-fetch@2.5.0",
				"universal-user-agent@2.1.0",
				"url-template@2.0.8",
			},
		},
		{
			ID: "@samverschueren/stream-to-observable@0.3.0",
			DependsOn: []string{
				"any-observable@0.3.0",
			},
		},
		{
			ID: "@storybook/addon-actions@4.1.18",
			DependsOn: []string{
				"@emotion/core@0.13.1",
				"@emotion/provider@0.11.2",
				"@emotion/styled@0.10.6",
				"@storybook/addons@4.1.18",
				"@storybook/components@4.1.18",
				"@storybook/core-events@4.1.18",
				"core-js@2.6.5",
				"deep-equal@1.0.1",
				"global@4.3.2",
				"lodash@4.17.11",
				"make-error@1.3.5",
				"prop-types@15.7.2",
				"react-inspector@2.3.1",
				"uuid@3.3.2",
			},
		},
		{
			ID: "@storybook/addon-info@4.1.18",
			DependsOn: []string{
				"@storybook/addons@4.1.18",
				"@storybook/client-logger@4.1.18",
				"@storybook/components@4.1.18",
				"core-js@2.6.5",
				"global@4.3.2",
				"marksy@6.1.0",
				"nested-object-assign@1.0.3",
				"prop-types@15.7.2",
				"react-addons-create-fragment@15.6.2",
				"react-lifecycles-compat@3.0.4",
				"util-deprecate@1.0.2",
			},
		},
		{
			ID: "@storybook/addon-knobs@4.1.18",
			DependsOn: []string{
				"@emotion/styled@0.10.6",
				"@storybook/addons@4.1.18",
				"@storybook/components@4.1.18",
				"@storybook/core-events@4.1.18",
				"copy-to-clipboard@3.2.0",
				"core-js@2.6.5",
				"escape-html@1.0.3",
				"fast-deep-equal@2.0.1",
				"global@4.3.2",
				"prop-types@15.7.2",
				"qs@6.7.0",
				"react-color@2.17.3",
				"react-lifecycles-compat@3.0.4",
				"util-deprecate@1.0.2",
			},
		},
		{
			ID: "@storybook/addons@4.1.18",
			DependsOn: []string{
				"@storybook/channels@4.1.18",
				"@storybook/components@4.1.18",
				"global@4.3.2",
				"util-deprecate@1.0.2",
			},
		},
		{
			ID: "@storybook/channel-postmessage@4.1.18",
			DependsOn: []string{
				"@storybook/channels@4.1.18",
				"global@4.3.2",
				"json-stringify-safe@5.0.1",
			},
		},
		{
			ID: "@storybook/cli@4.1.18",
			DependsOn: []string{
				"@babel/core@7.4.4",
				"@babel/preset-env@7.4.4",
				"@babel/register@7.4.4",
				"@storybook/codemod@4.1.18",
				"chalk@2.4.2",
				"commander@2.20.0",
				"core-js@2.6.5",
				"cross-spawn@6.0.5",
				"inquirer@6.3.1",
				"jscodeshift@0.5.1",
				"json5@2.1.0",
				"merge-dirs@0.2.1",
				"semver@5.7.0",
				"shelljs@0.8.3",
				"update-notifier@2.5.0",
			},
		},
		{
			ID: "@storybook/codemod@4.1.18",
			DependsOn: []string{
				"core-js@2.6.5",
				"jscodeshift@0.5.1",
				"regenerator-runtime@0.12.1",
			},
		},
		{
			ID: "@storybook/components@4.1.18",
			DependsOn: []string{
				"@emotion/core@0.13.1",
				"@emotion/provider@0.11.2",
				"@emotion/styled@0.10.6",
				"global@4.3.2",
				"lodash@4.17.11",
				"prop-types@15.7.2",
				"react-inspector@2.3.1",
				"react-split-pane@0.1.87",
				"react-textarea-autosize@7.1.0",
				"render-fragment@0.1.1",
			},
		},
		{
			ID: "@storybook/core@4.1.18",
			DependsOn: []string{
				"@babel/plugin-proposal-class-properties@7.4.4",
				"@babel/preset-env@7.4.4",
				"@emotion/core@0.13.1",
				"@emotion/provider@0.11.2",
				"@emotion/styled@0.10.6",
				"@storybook/addons@4.1.18",
				"@storybook/channel-postmessage@4.1.18",
				"@storybook/client-logger@4.1.18",
				"@storybook/core-events@4.1.18",
				"@storybook/node-logger@4.1.18",
				"@storybook/ui@4.1.18",
				"airbnb-js-shims@2.2.0",
				"autoprefixer@9.5.1",
				"babel-plugin-macros@2.5.1",
				"babel-preset-minify@0.5.0",
				"boxen@2.1.0",
				"case-sensitive-paths-webpack-plugin@2.2.0",
				"chalk@2.4.2",
				"child-process-promise@2.2.1",
				"cli-table3@0.5.1",
				"commander@2.20.0",
				"common-tags@1.8.0",
				"core-js@2.6.5",
				"css-loader@1.0.1",
				"detect-port@1.3.0",
				"dotenv-webpack@1.7.0",
				"ejs@2.6.1",
				"eventemitter3@3.1.2",
				"express@4.16.4",
				"file-loader@2.0.0",
				"file-system-cache@1.0.5",
				"find-cache-dir@2.1.0",
				"fs-extra@7.0.1",
				"global@4.3.2",
				"html-webpack-plugin@4.0.0-beta.5",
				"inquirer@6.3.1",
				"interpret@1.2.0",
				"ip@1.1.5",
				"json5@2.1.0",
				"lazy-universal-dotenv@2.0.0",
				"node-fetch@2.5.0",
				"opn@5.5.0",
				"postcss-flexbugs-fixes@4.1.0",
				"postcss-loader@3.0.0",
				"pretty-hrtime@1.0.3",
				"prop-types@15.7.2",
				"qs@6.7.0",
				"raw-loader@0.5.1",
				"react-dev-utils@6.1.1",
				"redux@4.0.1",
				"regenerator-runtime@0.12.1",
				"resolve@1.10.1",
				"resolve-from@4.0.0",
				"semver@5.7.0",
				"serve-favicon@2.5.0",
				"shelljs@0.8.3",
				"spawn-promise@0.1.8",
				"style-loader@0.23.1",
				"svg-url-loader@2.3.2",
				"terser-webpack-plugin@1.2.4",
				"url-loader@1.1.2",
				"webpack@4.31.0",
				"webpack-dev-middleware@3.7.0",
				"webpack-hot-middleware@2.25.0",
			},
		},
		{
			ID: "@storybook/mantra-core@1.7.2",
			DependsOn: []string{
				"@storybook/react-komposer@2.0.5",
				"@storybook/react-simple-di@1.3.0",
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "@storybook/node-logger@4.1.18",
			DependsOn: []string{
				"chalk@2.4.2",
				"core-js@2.6.5",
				"npmlog@4.1.2",
				"pretty-hrtime@1.0.3",
				"regenerator-runtime@0.12.1",
			},
		},
		{
			ID: "@storybook/podda@1.2.3",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"immutable@3.8.2",
			},
		},
		{
			ID: "@storybook/react-komposer@2.0.5",
			DependsOn: []string{
				"@storybook/react-stubber@1.0.1",
				"babel-runtime@6.26.0",
				"hoist-non-react-statics@1.2.0",
				"lodash@4.17.11",
				"shallowequal@1.1.0",
			},
		},
		{
			ID: "@storybook/react-simple-di@1.3.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"create-react-class@15.6.3",
				"hoist-non-react-statics@1.2.0",
				"prop-types@15.7.2",
			},
		},
		{
			ID: "@storybook/react-stubber@1.0.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "@storybook/react@4.1.18",
			DependsOn: []string{
				"@babel/plugin-transform-react-constant-elements@7.2.0",
				"@babel/preset-flow@7.0.0",
				"@babel/preset-react@7.0.0",
				"@emotion/styled@0.10.6",
				"@storybook/core@4.1.18",
				"@storybook/node-logger@4.1.18",
				"@svgr/webpack@4.2.0",
				"babel-plugin-named-asset-import@0.2.3",
				"babel-plugin-react-docgen@2.0.2",
				"babel-preset-react-app@6.1.0",
				"common-tags@1.8.0",
				"core-js@2.6.5",
				"global@4.3.2",
				"lodash@4.17.11",
				"mini-css-extract-plugin@0.4.5",
				"prop-types@15.7.2",
				"react-dev-utils@6.1.1",
				"regenerator-runtime@0.12.1",
				"semver@5.7.0",
				"webpack@4.31.0",
			},
		},
		{
			ID: "@storybook/ui@4.1.18",
			DependsOn: []string{
				"@emotion/core@0.13.1",
				"@emotion/provider@0.11.2",
				"@emotion/styled@0.10.6",
				"@storybook/components@4.1.18",
				"@storybook/core-events@4.1.18",
				"@storybook/mantra-core@1.7.2",
				"@storybook/podda@1.2.3",
				"@storybook/react-komposer@2.0.5",
				"deep-equal@1.0.1",
				"eventemitter3@3.1.2",
				"fuse.js@3.4.4",
				"global@4.3.2",
				"keycode@2.2.0",
				"lodash@4.17.11",
				"prop-types@15.7.2",
				"qs@6.7.0",
				"react@16.8.6",
				"react-dom@16.8.6",
				"react-fuzzy@0.5.2",
				"react-lifecycles-compat@3.0.4",
				"react-modal@3.8.1",
				"react-treebeard@3.1.0",
			},
		},
		{
			ID: "@svgr/babel-preset@4.2.0",
			DependsOn: []string{
				"@svgr/babel-plugin-add-jsx-attribute@4.2.0",
				"@svgr/babel-plugin-remove-jsx-attribute@4.2.0",
				"@svgr/babel-plugin-remove-jsx-empty-expression@4.2.0",
				"@svgr/babel-plugin-replace-jsx-attribute-value@4.2.0",
				"@svgr/babel-plugin-svg-dynamic-title@4.2.0",
				"@svgr/babel-plugin-svg-em-dimensions@4.2.0",
				"@svgr/babel-plugin-transform-react-native-svg@4.2.0",
				"@svgr/babel-plugin-transform-svg-component@4.2.0",
			},
		},
		{
			ID: "@svgr/core@4.2.0",
			DependsOn: []string{
				"@svgr/plugin-jsx@4.2.0",
				"camelcase@5.3.1",
				"cosmiconfig@5.2.1",
			},
		},
		{
			ID: "@svgr/hast-util-to-babel-ast@4.2.0",
			DependsOn: []string{
				"@babel/types@7.4.4",
			},
		},
		{
			ID: "@svgr/plugin-jsx@4.2.0",
			DependsOn: []string{
				"@babel/core@7.4.4",
				"@svgr/babel-preset@4.2.0",
				"@svgr/hast-util-to-babel-ast@4.2.0",
				"rehype-parse@6.0.0",
				"unified@7.1.0",
				"vfile@4.0.0",
			},
		},
		{
			ID: "@svgr/plugin-svgo@4.2.0",
			DependsOn: []string{
				"cosmiconfig@5.2.1",
				"merge-deep@3.0.2",
				"svgo@1.2.2",
			},
		},
		{
			ID: "@svgr/webpack@4.2.0",
			DependsOn: []string{
				"@babel/core@7.4.4",
				"@babel/plugin-transform-react-constant-elements@7.2.0",
				"@babel/preset-env@7.4.4",
				"@babel/preset-react@7.0.0",
				"@svgr/core@4.2.0",
				"@svgr/plugin-jsx@4.2.0",
				"@svgr/plugin-svgo@4.2.0",
				"loader-utils@1.2.3",
			},
		},
		{
			ID: "@types/glob@7.1.1",
			DependsOn: []string{
				"@types/events@3.0.0",
				"@types/minimatch@3.0.3",
				"@types/node@12.0.2",
			},
		},
		{
			ID: "@types/jss@9.5.8",
			DependsOn: []string{
				"csstype@2.6.4",
				"indefinite-observable@1.0.2",
			},
		},
		{
			ID: "@types/react-transition-group@2.9.1",
			DependsOn: []string{
				"@types/react@16.8.17",
			},
		},
		{
			ID: "@types/react@16.8.17",
			DependsOn: []string{
				"@types/prop-types@15.7.1",
				"csstype@2.6.4",
			},
		},
		{
			ID: "@types/vfile-message@1.0.1",
			DependsOn: []string{
				"@types/node@12.0.2",
				"@types/unist@2.0.3",
			},
		},
		{
			ID: "@types/vfile@3.0.2",
			DependsOn: []string{
				"@types/node@12.0.2",
				"@types/unist@2.0.3",
				"@types/vfile-message@1.0.1",
			},
		},
		{
			ID: "@webassemblyjs/ast@1.8.5",
			DependsOn: []string{
				"@webassemblyjs/helper-module-context@1.8.5",
				"@webassemblyjs/helper-wasm-bytecode@1.8.5",
				"@webassemblyjs/wast-parser@1.8.5",
			},
		},
		{
			ID: "@webassemblyjs/helper-code-frame@1.8.5",
			DependsOn: []string{
				"@webassemblyjs/wast-printer@1.8.5",
			},
		},
		{
			ID: "@webassemblyjs/helper-module-context@1.8.5",
			DependsOn: []string{
				"@webassemblyjs/ast@1.8.5",
				"mamacro@0.0.3",
			},
		},
		{
			ID: "@webassemblyjs/helper-wasm-section@1.8.5",
			DependsOn: []string{
				"@webassemblyjs/ast@1.8.5",
				"@webassemblyjs/helper-buffer@1.8.5",
				"@webassemblyjs/helper-wasm-bytecode@1.8.5",
				"@webassemblyjs/wasm-gen@1.8.5",
			},
		},
		{
			ID: "@webassemblyjs/ieee754@1.8.5",
			DependsOn: []string{
				"@xtuc/ieee754@1.2.0",
			},
		},
		{
			ID: "@webassemblyjs/leb128@1.8.5",
			DependsOn: []string{
				"@xtuc/long@4.2.2",
			},
		},
		{
			ID: "@webassemblyjs/wasm-edit@1.8.5",
			DependsOn: []string{
				"@webassemblyjs/ast@1.8.5",
				"@webassemblyjs/helper-buffer@1.8.5",
				"@webassemblyjs/helper-wasm-bytecode@1.8.5",
				"@webassemblyjs/helper-wasm-section@1.8.5",
				"@webassemblyjs/wasm-gen@1.8.5",
				"@webassemblyjs/wasm-opt@1.8.5",
				"@webassemblyjs/wasm-parser@1.8.5",
				"@webassemblyjs/wast-printer@1.8.5",
			},
		},
		{
			ID: "@webassemblyjs/wasm-gen@1.8.5",
			DependsOn: []string{
				"@webassemblyjs/ast@1.8.5",
				"@webassemblyjs/helper-wasm-bytecode@1.8.5",
				"@webassemblyjs/ieee754@1.8.5",
				"@webassemblyjs/leb128@1.8.5",
				"@webassemblyjs/utf8@1.8.5",
			},
		},
		{
			ID: "@webassemblyjs/wasm-opt@1.8.5",
			DependsOn: []string{
				"@webassemblyjs/ast@1.8.5",
				"@webassemblyjs/helper-buffer@1.8.5",
				"@webassemblyjs/wasm-gen@1.8.5",
				"@webassemblyjs/wasm-parser@1.8.5",
			},
		},
		{
			ID: "@webassemblyjs/wasm-parser@1.8.5",
			DependsOn: []string{
				"@webassemblyjs/ast@1.8.5",
				"@webassemblyjs/helper-api-error@1.8.5",
				"@webassemblyjs/helper-wasm-bytecode@1.8.5",
				"@webassemblyjs/ieee754@1.8.5",
				"@webassemblyjs/leb128@1.8.5",
				"@webassemblyjs/utf8@1.8.5",
			},
		},
		{
			ID: "@webassemblyjs/wast-parser@1.8.5",
			DependsOn: []string{
				"@webassemblyjs/ast@1.8.5",
				"@webassemblyjs/floating-point-hex-parser@1.8.5",
				"@webassemblyjs/helper-api-error@1.8.5",
				"@webassemblyjs/helper-code-frame@1.8.5",
				"@webassemblyjs/helper-fsm@1.8.5",
				"@xtuc/long@4.2.2",
			},
		},
		{
			ID: "@webassemblyjs/wast-printer@1.8.5",
			DependsOn: []string{
				"@webassemblyjs/ast@1.8.5",
				"@webassemblyjs/wast-parser@1.8.5",
				"@xtuc/long@4.2.2",
			},
		},
		{
			ID: "JSONStream@1.3.5",
			DependsOn: []string{
				"jsonparse@1.3.1",
				"through@2.3.8",
			},
		},
		{
			ID: "accepts@1.3.7",
			DependsOn: []string{
				"mime-types@2.1.24",
				"negotiator@0.6.2",
			},
		},
		{
			ID: "acorn-globals@4.3.2",
			DependsOn: []string{
				"acorn@6.1.1",
				"acorn-walk@6.1.1",
			},
		},
		{
			ID: "agent-base@4.2.1",
			DependsOn: []string{
				"es6-promisify@5.0.0",
			},
		},
		{
			ID: "agentkeepalive@3.5.2",
			DependsOn: []string{
				"humanize-ms@1.2.1",
			},
		},
		{
			ID: "airbnb-js-shims@2.2.0",
			DependsOn: []string{
				"array-includes@3.0.3",
				"array.prototype.flat@1.2.1",
				"array.prototype.flatmap@1.2.1",
				"es5-shim@4.5.13",
				"es6-shim@0.35.5",
				"function.prototype.name@1.1.0",
				"globalthis@1.0.0",
				"object.entries@1.1.0",
				"object.fromentries@2.0.0",
				"object.getownpropertydescriptors@2.0.3",
				"object.values@1.1.0",
				"promise.allsettled@1.0.1",
				"promise.prototype.finally@3.1.0",
				"string.prototype.matchall@3.0.1",
				"string.prototype.padend@3.0.0",
				"string.prototype.padstart@3.0.0",
				"symbol.prototype.description@1.0.0",
			},
		},
		{
			ID: "airbnb-prop-types@2.13.2",
			DependsOn: []string{
				"array.prototype.find@2.0.4",
				"function.prototype.name@1.1.0",
				"has@1.0.3",
				"is-regex@1.0.4",
				"object-is@1.0.1",
				"object.assign@4.1.0",
				"object.entries@1.1.0",
				"prop-types@15.7.2",
				"prop-types-exact@1.2.0",
				"react-is@16.8.6",
			},
		},
		{
			ID: "ajv@6.10.0",
			DependsOn: []string{
				"fast-deep-equal@2.0.1",
				"fast-json-stable-stringify@2.0.0",
				"json-schema-traverse@0.4.1",
				"uri-js@4.2.2",
			},
		},
		{
			ID: "ansi-align@2.0.0",
			DependsOn: []string{
				"string-width@2.1.1",
			},
		},
		{
			ID: "ansi-align@3.0.0",
			DependsOn: []string{
				"string-width@3.1.0",
			},
		},
		{
			ID: "ansi-styles@3.2.1",
			DependsOn: []string{
				"color-convert@1.9.3",
			},
		},
		{
			ID: "anymatch@1.3.2",
			DependsOn: []string{
				"micromatch@2.3.11",
				"normalize-path@2.1.1",
			},
		},
		{
			ID: "anymatch@2.0.0",
			DependsOn: []string{
				"micromatch@3.1.10",
				"normalize-path@2.1.1",
			},
		},
		{
			ID: "append-transform@0.4.0",
			DependsOn: []string{
				"default-require-extensions@1.0.0",
			},
		},
		{
			ID: "are-we-there-yet@1.1.5",
			DependsOn: []string{
				"delegates@1.0.0",
				"readable-stream@2.3.6",
			},
		},
		{
			ID: "argparse@1.0.10",
			DependsOn: []string{
				"sprintf-js@1.0.3",
			},
		},
		{
			ID: "aria-query@3.0.0",
			DependsOn: []string{
				"ast-types-flow@0.0.7",
				"commander@2.20.0",
			},
		},
		{
			ID: "arr-diff@2.0.0",
			DependsOn: []string{
				"arr-flatten@1.1.0",
			},
		},
		{
			ID: "array-includes@3.0.3",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
			},
		},
		{
			ID: "array-union@1.0.2",
			DependsOn: []string{
				"array-uniq@1.0.3",
			},
		},
		{
			ID: "array.prototype.find@2.0.4",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
			},
		},
		{
			ID: "array.prototype.flat@1.2.1",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
				"function-bind@1.1.1",
			},
		},
		{
			ID: "array.prototype.flatmap@1.2.1",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
				"function-bind@1.1.1",
			},
		},
		{
			ID: "asn1.js@4.10.1",
			DependsOn: []string{
				"bn.js@4.11.8",
				"inherits@2.0.3",
				"minimalistic-assert@1.0.1",
			},
		},
		{
			ID: "asn1@0.2.4",
			DependsOn: []string{
				"safer-buffer@2.1.2",
			},
		},
		{
			ID: "assert@1.5.0",
			DependsOn: []string{
				"object-assign@4.1.1",
				"util@0.10.3",
			},
		},
		{
			ID: "async@2.6.2",
			DependsOn: []string{
				"lodash@4.17.11",
			},
		},
		{
			ID: "attr-accept@1.1.3",
			DependsOn: []string{
				"core-js@2.6.5",
			},
		},
		{
			ID: "autodll-webpack-plugin@0.4.2",
			DependsOn: []string{
				"bluebird@3.5.4",
				"del@3.0.0",
				"find-cache-dir@1.0.0",
				"lodash@4.17.11",
				"make-dir@1.3.0",
				"memory-fs@0.4.1",
				"read-pkg@2.0.0",
				"tapable@1.1.3",
				"webpack-merge@4.2.1",
				"webpack-sources@1.3.0",
			},
		},
		{
			ID: "autoprefixer@8.6.5",
			DependsOn: []string{
				"browserslist@3.2.8",
				"caniuse-lite@1.0.30000967",
				"normalize-range@0.1.2",
				"num2fraction@1.2.2",
				"postcss@6.0.23",
				"postcss-value-parser@3.3.1",
			},
		},
		{
			ID: "autoprefixer@9.5.1",
			DependsOn: []string{
				"browserslist@4.6.0",
				"caniuse-lite@1.0.30000967",
				"normalize-range@0.1.2",
				"num2fraction@1.2.2",
				"postcss@7.0.16",
				"postcss-value-parser@3.3.1",
			},
		},
		{
			ID: "axios@0.18.0",
			DependsOn: []string{
				"follow-redirects@1.7.0",
				"is-buffer@1.1.6",
			},
		},
		{
			ID: "axobject-query@2.0.2",
			DependsOn: []string{
				"ast-types-flow@0.0.7",
			},
		},
		{
			ID: "babel-cli@6.26.0",
			DependsOn: []string{
				"babel-core@6.26.3",
				"babel-polyfill@6.26.0",
				"babel-register@6.26.0",
				"babel-runtime@6.26.0",
				"commander@2.20.0",
				"convert-source-map@1.6.0",
				"fs-readdir-recursive@1.1.0",
				"glob@7.1.4",
				"lodash@4.17.11",
				"output-file-sync@1.1.2",
				"path-is-absolute@1.0.1",
				"slash@1.0.0",
				"source-map@0.5.7",
				"v8flags@2.1.1",
			},
		},
		{
			ID: "babel-code-frame@6.26.0",
			DependsOn: []string{
				"chalk@1.1.3",
				"esutils@2.0.2",
				"js-tokens@3.0.2",
			},
		},
		{
			ID: "babel-core@6.26.3",
			DependsOn: []string{
				"babel-code-frame@6.26.0",
				"babel-generator@6.26.1",
				"babel-helpers@6.24.1",
				"babel-messages@6.23.0",
				"babel-register@6.26.0",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
				"babylon@6.18.0",
				"convert-source-map@1.6.0",
				"debug@2.6.9",
				"json5@0.5.1",
				"lodash@4.17.11",
				"minimatch@3.0.4",
				"path-is-absolute@1.0.1",
				"private@0.1.8",
				"slash@1.0.0",
				"source-map@0.5.7",
			},
		},
		{
			ID: "babel-eslint@8.2.6",
			DependsOn: []string{
				"@babel/code-frame@7.0.0-beta.44",
				"@babel/traverse@7.0.0-beta.44",
				"@babel/types@7.0.0-beta.44",
				"babylon@7.0.0-beta.44",
				"eslint-scope@3.7.1",
				"eslint-visitor-keys@1.0.0",
			},
		},
		{
			ID: "babel-generator@6.26.1",
			DependsOn: []string{
				"babel-messages@6.23.0",
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
				"detect-indent@4.0.0",
				"jsesc@1.3.0",
				"lodash@4.17.11",
				"source-map@0.5.7",
				"trim-right@1.0.1",
			},
		},
		{
			ID: "babel-helper-bindify-decorators@6.24.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-helper-builder-binary-assignment-operator-visitor@6.24.1",
			DependsOn: []string{
				"babel-helper-explode-assignable-expression@6.24.1",
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-helper-builder-react-jsx@6.26.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
				"esutils@2.0.2",
			},
		},
		{
			ID: "babel-helper-call-delegate@6.24.1",
			DependsOn: []string{
				"babel-helper-hoist-variables@6.24.1",
				"babel-runtime@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-helper-define-map@6.26.0",
			DependsOn: []string{
				"babel-helper-function-name@6.24.1",
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
				"lodash@4.17.11",
			},
		},
		{
			ID: "babel-helper-explode-assignable-expression@6.24.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-helper-explode-class@6.24.1",
			DependsOn: []string{
				"babel-helper-bindify-decorators@6.24.1",
				"babel-runtime@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-helper-function-name@6.24.1",
			DependsOn: []string{
				"babel-helper-get-function-arity@6.24.1",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-helper-get-function-arity@6.24.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-helper-hoist-variables@6.24.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-helper-optimise-call-expression@6.24.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-helper-regex@6.26.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
				"lodash@4.17.11",
			},
		},
		{
			ID: "babel-helper-remap-async-to-generator@6.24.1",
			DependsOn: []string{
				"babel-helper-function-name@6.24.1",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-helper-replace-supers@6.24.1",
			DependsOn: []string{
				"babel-helper-optimise-call-expression@6.24.1",
				"babel-messages@6.23.0",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-helpers@6.24.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
			},
		},
		{
			ID: "babel-jest@23.6.0",
			DependsOn: []string{
				"babel-plugin-istanbul@4.1.6",
				"babel-preset-jest@23.2.0",
			},
		},
		{
			ID: "babel-loader@8.0.4",
			DependsOn: []string{
				"find-cache-dir@1.0.0",
				"loader-utils@1.2.3",
				"mkdirp@0.5.1",
				"util.promisify@1.0.0",
			},
		},
		{
			ID: "babel-loader@7.1.5",
			DependsOn: []string{
				"find-cache-dir@1.0.0",
				"loader-utils@1.2.3",
				"mkdirp@0.5.1",
			},
		},
		{
			ID: "babel-messages@6.23.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-check-es2015-constants@6.22.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-dynamic-import-node@2.2.0",
			DependsOn: []string{
				"object.assign@4.1.0",
			},
		},
		{
			ID: "babel-plugin-istanbul@4.1.6",
			DependsOn: []string{
				"babel-plugin-syntax-object-rest-spread@6.13.0",
				"find-up@2.1.0",
				"istanbul-lib-instrument@1.10.2",
				"test-exclude@4.2.3",
			},
		},
		{
			ID: "babel-plugin-macros@2.4.2",
			DependsOn: []string{
				"cosmiconfig@5.2.1",
				"resolve@1.10.1",
			},
		},
		{
			ID: "babel-plugin-macros@2.5.1",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"cosmiconfig@5.2.1",
				"resolve@1.10.1",
			},
		},
		{
			ID: "babel-plugin-minify-constant-folding@0.5.0",
			DependsOn: []string{
				"babel-helper-evaluate-path@0.5.0",
			},
		},
		{
			ID: "babel-plugin-minify-dead-code-elimination@0.5.0",
			DependsOn: []string{
				"babel-helper-evaluate-path@0.5.0",
				"babel-helper-mark-eval-scopes@0.4.3",
				"babel-helper-remove-or-void@0.4.3",
				"lodash.some@4.6.0",
			},
		},
		{
			ID: "babel-plugin-minify-flip-comparisons@0.4.3",
			DependsOn: []string{
				"babel-helper-is-void-0@0.4.3",
			},
		},
		{
			ID: "babel-plugin-minify-guarded-expressions@0.4.3",
			DependsOn: []string{
				"babel-helper-flip-expressions@0.4.3",
			},
		},
		{
			ID: "babel-plugin-minify-mangle-names@0.5.0",
			DependsOn: []string{
				"babel-helper-mark-eval-scopes@0.4.3",
			},
		},
		{
			ID: "babel-plugin-minify-simplify@0.5.0",
			DependsOn: []string{
				"babel-helper-flip-expressions@0.4.3",
				"babel-helper-is-nodes-equiv@0.0.1",
				"babel-helper-to-multiple-sequence-expressions@0.5.0",
			},
		},
		{
			ID: "babel-plugin-minify-type-constructors@0.4.3",
			DependsOn: []string{
				"babel-helper-is-void-0@0.4.3",
			},
		},
		{
			ID: "babel-plugin-react-docgen@2.0.2",
			DependsOn: []string{
				"lodash@4.17.11",
				"react-docgen@3.0.0",
				"recast@0.14.7",
			},
		},
		{
			ID: "babel-plugin-styled-components@1.10.0",
			DependsOn: []string{
				"@babel/helper-annotate-as-pure@7.0.0",
				"@babel/helper-module-imports@7.0.0",
				"babel-plugin-syntax-jsx@6.18.0",
				"lodash@4.17.11",
			},
		},
		{
			ID: "babel-plugin-transform-async-generator-functions@6.24.1",
			DependsOn: []string{
				"babel-helper-remap-async-to-generator@6.24.1",
				"babel-plugin-syntax-async-generators@6.13.0",
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-async-to-generator@6.24.1",
			DependsOn: []string{
				"babel-helper-remap-async-to-generator@6.24.1",
				"babel-plugin-syntax-async-functions@6.13.0",
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-class-constructor-call@6.24.1",
			DependsOn: []string{
				"babel-plugin-syntax-class-constructor-call@6.18.0",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-class-properties@6.24.1",
			DependsOn: []string{
				"babel-helper-function-name@6.24.1",
				"babel-plugin-syntax-class-properties@6.13.0",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-decorators@6.24.1",
			DependsOn: []string{
				"babel-helper-explode-class@6.24.1",
				"babel-plugin-syntax-decorators@6.13.0",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-arrow-functions@6.22.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-block-scoped-functions@6.22.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-block-scoping@6.26.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
				"lodash@4.17.11",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-classes@6.24.1",
			DependsOn: []string{
				"babel-helper-define-map@6.26.0",
				"babel-helper-function-name@6.24.1",
				"babel-helper-optimise-call-expression@6.24.1",
				"babel-helper-replace-supers@6.24.1",
				"babel-messages@6.23.0",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-computed-properties@6.24.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-destructuring@6.23.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-duplicate-keys@6.24.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-for-of@6.23.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-function-name@6.24.1",
			DependsOn: []string{
				"babel-helper-function-name@6.24.1",
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-literals@6.22.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-modules-amd@6.24.1",
			DependsOn: []string{
				"babel-plugin-transform-es2015-modules-commonjs@6.26.2",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-modules-commonjs@6.26.2",
			DependsOn: []string{
				"babel-plugin-transform-strict-mode@6.24.1",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-modules-systemjs@6.24.1",
			DependsOn: []string{
				"babel-helper-hoist-variables@6.24.1",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-modules-umd@6.24.1",
			DependsOn: []string{
				"babel-plugin-transform-es2015-modules-amd@6.24.1",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-object-super@6.24.1",
			DependsOn: []string{
				"babel-helper-replace-supers@6.24.1",
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-parameters@6.24.1",
			DependsOn: []string{
				"babel-helper-call-delegate@6.24.1",
				"babel-helper-get-function-arity@6.24.1",
				"babel-runtime@6.26.0",
				"babel-template@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-shorthand-properties@6.24.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-spread@6.22.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-sticky-regex@6.24.1",
			DependsOn: []string{
				"babel-helper-regex@6.26.0",
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-template-literals@6.22.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-typeof-symbol@6.23.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-es2015-unicode-regex@6.24.1",
			DependsOn: []string{
				"babel-helper-regex@6.26.0",
				"babel-runtime@6.26.0",
				"regexpu-core@2.0.0",
			},
		},
		{
			ID: "babel-plugin-transform-exponentiation-operator@6.24.1",
			DependsOn: []string{
				"babel-helper-builder-binary-assignment-operator-visitor@6.24.1",
				"babel-plugin-syntax-exponentiation-operator@6.13.0",
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-export-extensions@6.22.0",
			DependsOn: []string{
				"babel-plugin-syntax-export-extensions@6.13.0",
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-flow-strip-types@6.22.0",
			DependsOn: []string{
				"babel-plugin-syntax-flow@6.18.0",
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-object-rest-spread@6.26.0",
			DependsOn: []string{
				"babel-plugin-syntax-object-rest-spread@6.13.0",
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-property-literals@6.9.4",
			DependsOn: []string{
				"esutils@2.0.2",
			},
		},
		{
			ID: "babel-plugin-transform-react-display-name@6.25.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-react-jsx-self@6.22.0",
			DependsOn: []string{
				"babel-plugin-syntax-jsx@6.18.0",
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-react-jsx-source@6.22.0",
			DependsOn: []string{
				"babel-plugin-syntax-jsx@6.18.0",
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-react-jsx@6.24.1",
			DependsOn: []string{
				"babel-helper-builder-react-jsx@6.26.0",
				"babel-plugin-syntax-jsx@6.18.0",
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-regenerator@6.26.0",
			DependsOn: []string{
				"regenerator-transform@0.10.1",
			},
		},
		{
			ID: "babel-plugin-transform-remove-undefined@0.5.0",
			DependsOn: []string{
				"babel-helper-evaluate-path@0.5.0",
			},
		},
		{
			ID: "babel-plugin-transform-runtime@6.23.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
			},
		},
		{
			ID: "babel-plugin-transform-strict-mode@6.24.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
			},
		},
		{
			ID: "babel-polyfill@6.26.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"core-js@2.6.5",
				"regenerator-runtime@0.10.5",
			},
		},
		{
			ID: "babel-preset-env@1.7.0",
			DependsOn: []string{
				"babel-plugin-check-es2015-constants@6.22.0",
				"babel-plugin-syntax-trailing-function-commas@6.22.0",
				"babel-plugin-transform-async-to-generator@6.24.1",
				"babel-plugin-transform-es2015-arrow-functions@6.22.0",
				"babel-plugin-transform-es2015-block-scoped-functions@6.22.0",
				"babel-plugin-transform-es2015-block-scoping@6.26.0",
				"babel-plugin-transform-es2015-classes@6.24.1",
				"babel-plugin-transform-es2015-computed-properties@6.24.1",
				"babel-plugin-transform-es2015-destructuring@6.23.0",
				"babel-plugin-transform-es2015-duplicate-keys@6.24.1",
				"babel-plugin-transform-es2015-for-of@6.23.0",
				"babel-plugin-transform-es2015-function-name@6.24.1",
				"babel-plugin-transform-es2015-literals@6.22.0",
				"babel-plugin-transform-es2015-modules-amd@6.24.1",
				"babel-plugin-transform-es2015-modules-commonjs@6.26.2",
				"babel-plugin-transform-es2015-modules-systemjs@6.24.1",
				"babel-plugin-transform-es2015-modules-umd@6.24.1",
				"babel-plugin-transform-es2015-object-super@6.24.1",
				"babel-plugin-transform-es2015-parameters@6.24.1",
				"babel-plugin-transform-es2015-shorthand-properties@6.24.1",
				"babel-plugin-transform-es2015-spread@6.22.0",
				"babel-plugin-transform-es2015-sticky-regex@6.24.1",
				"babel-plugin-transform-es2015-template-literals@6.22.0",
				"babel-plugin-transform-es2015-typeof-symbol@6.23.0",
				"babel-plugin-transform-es2015-unicode-regex@6.24.1",
				"babel-plugin-transform-exponentiation-operator@6.24.1",
				"babel-plugin-transform-regenerator@6.26.0",
				"browserslist@3.2.8",
				"invariant@2.2.4",
				"semver@5.7.0",
			},
		},
		{
			ID: "babel-preset-es2015@6.24.1",
			DependsOn: []string{
				"babel-plugin-check-es2015-constants@6.22.0",
				"babel-plugin-transform-es2015-arrow-functions@6.22.0",
				"babel-plugin-transform-es2015-block-scoped-functions@6.22.0",
				"babel-plugin-transform-es2015-block-scoping@6.26.0",
				"babel-plugin-transform-es2015-classes@6.24.1",
				"babel-plugin-transform-es2015-computed-properties@6.24.1",
				"babel-plugin-transform-es2015-destructuring@6.23.0",
				"babel-plugin-transform-es2015-duplicate-keys@6.24.1",
				"babel-plugin-transform-es2015-for-of@6.23.0",
				"babel-plugin-transform-es2015-function-name@6.24.1",
				"babel-plugin-transform-es2015-literals@6.22.0",
				"babel-plugin-transform-es2015-modules-amd@6.24.1",
				"babel-plugin-transform-es2015-modules-commonjs@6.26.2",
				"babel-plugin-transform-es2015-modules-systemjs@6.24.1",
				"babel-plugin-transform-es2015-modules-umd@6.24.1",
				"babel-plugin-transform-es2015-object-super@6.24.1",
				"babel-plugin-transform-es2015-parameters@6.24.1",
				"babel-plugin-transform-es2015-shorthand-properties@6.24.1",
				"babel-plugin-transform-es2015-spread@6.22.0",
				"babel-plugin-transform-es2015-sticky-regex@6.24.1",
				"babel-plugin-transform-es2015-template-literals@6.22.0",
				"babel-plugin-transform-es2015-typeof-symbol@6.23.0",
				"babel-plugin-transform-es2015-unicode-regex@6.24.1",
				"babel-plugin-transform-regenerator@6.26.0",
			},
		},
		{
			ID: "babel-preset-flow@6.23.0",
			DependsOn: []string{
				"babel-plugin-transform-flow-strip-types@6.22.0",
			},
		},
		{
			ID: "babel-preset-jest@23.2.0",
			DependsOn: []string{
				"babel-plugin-jest-hoist@23.2.0",
				"babel-plugin-syntax-object-rest-spread@6.13.0",
			},
		},
		{
			ID: "babel-preset-minify@0.5.0",
			DependsOn: []string{
				"babel-plugin-minify-builtins@0.5.0",
				"babel-plugin-minify-constant-folding@0.5.0",
				"babel-plugin-minify-dead-code-elimination@0.5.0",
				"babel-plugin-minify-flip-comparisons@0.4.3",
				"babel-plugin-minify-guarded-expressions@0.4.3",
				"babel-plugin-minify-infinity@0.4.3",
				"babel-plugin-minify-mangle-names@0.5.0",
				"babel-plugin-minify-numeric-literals@0.4.3",
				"babel-plugin-minify-replace@0.5.0",
				"babel-plugin-minify-simplify@0.5.0",
				"babel-plugin-minify-type-constructors@0.4.3",
				"babel-plugin-transform-inline-consecutive-adds@0.4.3",
				"babel-plugin-transform-member-expression-literals@6.9.4",
				"babel-plugin-transform-merge-sibling-variables@6.9.4",
				"babel-plugin-transform-minify-booleans@6.9.4",
				"babel-plugin-transform-property-literals@6.9.4",
				"babel-plugin-transform-regexp-constructors@0.4.3",
				"babel-plugin-transform-remove-console@6.9.4",
				"babel-plugin-transform-remove-debugger@6.9.4",
				"babel-plugin-transform-remove-undefined@0.5.0",
				"babel-plugin-transform-simplify-comparison-operators@6.9.4",
				"babel-plugin-transform-undefined-to-void@6.9.4",
				"lodash.isplainobject@4.0.6",
			},
		},
		{
			ID: "babel-preset-react-app@6.1.0",
			DependsOn: []string{
				"@babel/core@7.1.0",
				"@babel/plugin-proposal-class-properties@7.1.0",
				"@babel/plugin-proposal-decorators@7.1.2",
				"@babel/plugin-proposal-object-rest-spread@7.0.0",
				"@babel/plugin-syntax-dynamic-import@7.0.0",
				"@babel/plugin-transform-classes@7.1.0",
				"@babel/plugin-transform-destructuring@7.0.0",
				"@babel/plugin-transform-flow-strip-types@7.0.0",
				"@babel/plugin-transform-react-constant-elements@7.0.0",
				"@babel/plugin-transform-react-display-name@7.0.0",
				"@babel/plugin-transform-runtime@7.1.0",
				"@babel/preset-env@7.1.0",
				"@babel/preset-react@7.0.0",
				"@babel/preset-typescript@7.1.0",
				"@babel/runtime@7.0.0",
				"babel-loader@8.0.4",
				"babel-plugin-dynamic-import-node@2.2.0",
				"babel-plugin-macros@2.4.2",
				"babel-plugin-transform-react-remove-prop-types@0.4.18",
			},
		},
		{
			ID: "babel-preset-react@6.24.1",
			DependsOn: []string{
				"babel-plugin-syntax-jsx@6.18.0",
				"babel-plugin-transform-react-display-name@6.25.0",
				"babel-plugin-transform-react-jsx@6.24.1",
				"babel-plugin-transform-react-jsx-self@6.22.0",
				"babel-plugin-transform-react-jsx-source@6.22.0",
				"babel-preset-flow@6.23.0",
			},
		},
		{
			ID: "babel-preset-stage-1@6.24.1",
			DependsOn: []string{
				"babel-plugin-transform-class-constructor-call@6.24.1",
				"babel-plugin-transform-export-extensions@6.22.0",
				"babel-preset-stage-2@6.24.1",
			},
		},
		{
			ID: "babel-preset-stage-2@6.24.1",
			DependsOn: []string{
				"babel-plugin-syntax-dynamic-import@6.18.0",
				"babel-plugin-transform-class-properties@6.24.1",
				"babel-plugin-transform-decorators@6.24.1",
				"babel-preset-stage-3@6.24.1",
			},
		},
		{
			ID: "babel-preset-stage-3@6.24.1",
			DependsOn: []string{
				"babel-plugin-syntax-trailing-function-commas@6.22.0",
				"babel-plugin-transform-async-generator-functions@6.24.1",
				"babel-plugin-transform-async-to-generator@6.24.1",
				"babel-plugin-transform-exponentiation-operator@6.24.1",
				"babel-plugin-transform-object-rest-spread@6.26.0",
			},
		},
		{
			ID: "babel-register@6.26.0",
			DependsOn: []string{
				"babel-core@6.26.3",
				"babel-runtime@6.26.0",
				"core-js@2.6.5",
				"home-or-tmp@2.0.0",
				"lodash@4.17.11",
				"mkdirp@0.5.1",
				"source-map-support@0.4.18",
			},
		},
		{
			ID: "babel-runtime@6.26.0",
			DependsOn: []string{
				"core-js@2.6.5",
				"regenerator-runtime@0.11.1",
			},
		},
		{
			ID: "babel-template@6.26.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
				"babylon@6.18.0",
				"lodash@4.17.11",
			},
		},
		{
			ID: "babel-traverse@6.26.0",
			DependsOn: []string{
				"babel-code-frame@6.26.0",
				"babel-messages@6.23.0",
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
				"babylon@6.18.0",
				"debug@2.6.9",
				"globals@9.18.0",
				"invariant@2.2.4",
				"lodash@4.17.11",
			},
		},
		{
			ID: "babel-types@6.26.0",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"esutils@2.0.2",
				"lodash@4.17.11",
				"to-fast-properties@1.0.3",
			},
		},
		{
			ID: "base@0.11.2",
			DependsOn: []string{
				"cache-base@1.0.1",
				"class-utils@0.3.6",
				"component-emitter@1.3.0",
				"define-property@1.0.0",
				"isobject@3.0.1",
				"mixin-deep@1.3.1",
				"pascalcase@0.1.1",
			},
		},
		{
			ID: "bcrypt-pbkdf@1.0.2",
			DependsOn: []string{
				"tweetnacl@0.14.5",
			},
		},
		{
			ID: "better-assert@1.0.2",
			DependsOn: []string{
				"callsite@1.0.0",
			},
		},
		{
			ID: "bfj@6.1.1",
			DependsOn: []string{
				"bluebird@3.5.4",
				"check-types@7.4.0",
				"hoopy@0.1.4",
				"tryer@1.0.1",
			},
		},
		{
			ID: "bin-links@1.1.2",
			DependsOn: []string{
				"bluebird@3.5.4",
				"cmd-shim@2.0.2",
				"gentle-fs@2.0.1",
				"graceful-fs@4.1.15",
				"write-file-atomic@2.4.2",
			},
		},
		{
			ID: "binary@0.3.0",
			DependsOn: []string{
				"buffers@0.1.1",
				"chainsaw@0.1.0",
			},
		},
		{
			ID: "block-stream@0.0.9",
			DependsOn: []string{
				"inherits@2.0.3",
			},
		},
		{
			ID: "body-parser@1.18.3",
			DependsOn: []string{
				"bytes@3.0.0",
				"content-type@1.0.4",
				"debug@2.6.9",
				"depd@1.1.2",
				"http-errors@1.6.3",
				"iconv-lite@0.4.23",
				"on-finished@2.3.0",
				"qs@6.5.2",
				"raw-body@2.3.3",
				"type-is@1.6.18",
			},
		},
		{
			ID: "bonjour@3.5.0",
			DependsOn: []string{
				"array-flatten@2.1.2",
				"deep-equal@1.0.1",
				"dns-equal@1.0.0",
				"dns-txt@2.0.2",
				"multicast-dns@6.2.3",
				"multicast-dns-service-types@1.1.0",
			},
		},
		{
			ID: "boxen@1.3.0",
			DependsOn: []string{
				"ansi-align@2.0.0",
				"camelcase@4.1.0",
				"chalk@2.4.2",
				"cli-boxes@1.0.0",
				"string-width@2.1.1",
				"term-size@1.2.0",
				"widest-line@2.0.1",
			},
		},
		{
			ID: "boxen@2.1.0",
			DependsOn: []string{
				"ansi-align@3.0.0",
				"camelcase@5.3.1",
				"chalk@2.4.2",
				"cli-boxes@1.0.0",
				"string-width@3.1.0",
				"term-size@1.2.0",
				"widest-line@2.0.1",
			},
		},
		{
			ID: "brace-expansion@1.1.11",
			DependsOn: []string{
				"balanced-match@1.0.0",
				"concat-map@0.0.1",
			},
		},
		{
			ID: "braces@1.8.5",
			DependsOn: []string{
				"expand-range@1.8.2",
				"preserve@0.2.0",
				"repeat-element@1.1.3",
			},
		},
		{
			ID: "braces@2.3.2",
			DependsOn: []string{
				"arr-flatten@1.1.0",
				"array-unique@0.3.2",
				"extend-shallow@2.0.1",
				"fill-range@4.0.0",
				"isobject@3.0.1",
				"repeat-element@1.1.3",
				"snapdragon@0.8.2",
				"snapdragon-node@2.1.1",
				"split-string@3.1.0",
				"to-regex@3.0.2",
			},
		},
		{
			ID: "browser-resolve@1.11.3",
			DependsOn: []string{
				"resolve@1.1.7",
			},
		},
		{
			ID: "browserify-aes@1.2.0",
			DependsOn: []string{
				"buffer-xor@1.0.3",
				"cipher-base@1.0.4",
				"create-hash@1.2.0",
				"evp_bytestokey@1.0.3",
				"inherits@2.0.3",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "browserify-cipher@1.0.1",
			DependsOn: []string{
				"browserify-aes@1.2.0",
				"browserify-des@1.0.2",
				"evp_bytestokey@1.0.3",
			},
		},
		{
			ID: "browserify-des@1.0.2",
			DependsOn: []string{
				"cipher-base@1.0.4",
				"des.js@1.0.0",
				"inherits@2.0.3",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "browserify-rsa@4.0.1",
			DependsOn: []string{
				"bn.js@4.11.8",
				"randombytes@2.1.0",
			},
		},
		{
			ID: "browserify-sign@4.0.4",
			DependsOn: []string{
				"bn.js@4.11.8",
				"browserify-rsa@4.0.1",
				"create-hash@1.2.0",
				"create-hmac@1.1.7",
				"elliptic@6.4.1",
				"inherits@2.0.3",
				"parse-asn1@5.1.4",
			},
		},
		{
			ID: "browserify-zlib@0.2.0",
			DependsOn: []string{
				"pako@1.0.10",
			},
		},
		{
			ID: "browserslist@4.1.1",
			DependsOn: []string{
				"caniuse-lite@1.0.30000967",
				"electron-to-chromium@1.3.134",
				"node-releases@1.1.19",
			},
		},
		{
			ID: "browserslist@3.2.8",
			DependsOn: []string{
				"caniuse-lite@1.0.30000967",
				"electron-to-chromium@1.3.134",
			},
		},
		{
			ID: "browserslist@4.6.0",
			DependsOn: []string{
				"caniuse-lite@1.0.30000967",
				"electron-to-chromium@1.3.134",
				"node-releases@1.1.19",
			},
		},
		{
			ID: "bser@2.0.0",
			DependsOn: []string{
				"node-int64@0.4.0",
			},
		},
		{
			ID: "buffer@4.9.1",
			DependsOn: []string{
				"base64-js@1.3.0",
				"ieee754@1.1.13",
				"isarray@1.0.0",
			},
		},
		{
			ID: "cacache@10.0.4",
			DependsOn: []string{
				"bluebird@3.5.4",
				"chownr@1.1.1",
				"glob@7.1.4",
				"graceful-fs@4.1.15",
				"lru-cache@4.1.5",
				"mississippi@2.0.0",
				"mkdirp@0.5.1",
				"move-concurrently@1.0.1",
				"promise-inflight@1.0.1",
				"rimraf@2.6.3",
				"ssri@5.3.0",
				"unique-filename@1.1.1",
				"y18n@4.0.0",
			},
		},
		{
			ID: "cacache@11.3.2",
			DependsOn: []string{
				"bluebird@3.5.4",
				"chownr@1.1.1",
				"figgy-pudding@3.5.1",
				"glob@7.1.4",
				"graceful-fs@4.1.15",
				"lru-cache@5.1.1",
				"mississippi@3.0.0",
				"mkdirp@0.5.1",
				"move-concurrently@1.0.1",
				"promise-inflight@1.0.1",
				"rimraf@2.6.3",
				"ssri@6.0.1",
				"unique-filename@1.1.1",
				"y18n@4.0.0",
			},
		},
		{
			ID: "cache-base@1.0.1",
			DependsOn: []string{
				"collection-visit@1.0.0",
				"component-emitter@1.3.0",
				"get-value@2.0.6",
				"has-value@1.0.0",
				"isobject@3.0.1",
				"set-value@2.0.0",
				"to-object-path@0.3.0",
				"union-value@1.0.0",
				"unset-value@1.0.0",
			},
		},
		{
			ID: "cache-loader@1.2.5",
			DependsOn: []string{
				"loader-utils@1.2.3",
				"mkdirp@0.5.1",
				"neo-async@2.6.1",
				"schema-utils@0.4.7",
			},
		},
		{
			ID: "caller-callsite@2.0.0",
			DependsOn: []string{
				"callsites@2.0.0",
			},
		},
		{
			ID: "caller-path@2.0.0",
			DependsOn: []string{
				"caller-callsite@2.0.0",
			},
		},
		{
			ID: "camel-case@3.0.0",
			DependsOn: []string{
				"no-case@2.3.2",
				"upper-case@1.1.3",
			},
		},
		{
			ID: "capture-exit@1.2.0",
			DependsOn: []string{
				"rsvp@3.6.2",
			},
		},
		{
			ID: "chainsaw@0.1.0",
			DependsOn: []string{
				"traverse@0.3.9",
			},
		},
		{
			ID: "chalk@2.4.1",
			DependsOn: []string{
				"ansi-styles@3.2.1",
				"escape-string-regexp@1.0.5",
				"supports-color@5.5.0",
			},
		},
		{
			ID: "chalk@1.1.3",
			DependsOn: []string{
				"ansi-styles@2.2.1",
				"escape-string-regexp@1.0.5",
				"has-ansi@2.0.0",
				"strip-ansi@3.0.1",
				"supports-color@2.0.0",
			},
		},
		{
			ID: "chalk@2.4.2",
			DependsOn: []string{
				"ansi-styles@3.2.1",
				"escape-string-regexp@1.0.5",
				"supports-color@5.5.0",
			},
		},
		{
			ID: "chalk@0.4.0",
			DependsOn: []string{
				"ansi-styles@1.0.0",
				"has-color@0.1.7",
				"strip-ansi@0.1.1",
			},
		},
		{
			ID: "cheerio@1.0.0-rc.3",
			DependsOn: []string{
				"css-select@1.2.0",
				"dom-serializer@0.1.1",
				"entities@1.1.2",
				"htmlparser2@3.10.1",
				"lodash@4.17.11",
				"parse5@3.0.3",
			},
		},
		{
			ID: "child-process-promise@2.2.1",
			DependsOn: []string{
				"cross-spawn@4.0.2",
				"node-version@1.2.0",
				"promise-polyfill@6.1.0",
			},
		},
		{
			ID: "chokidar@1.7.0",
			DependsOn: []string{
				"anymatch@1.3.2",
				"async-each@1.0.3",
				"glob-parent@2.0.0",
				"inherits@2.0.3",
				"is-binary-path@1.0.1",
				"is-glob@2.0.1",
				"path-is-absolute@1.0.1",
				"readdirp@2.2.1",
			},
		},
		{
			ID: "chokidar@2.1.5",
			DependsOn: []string{
				"anymatch@2.0.0",
				"async-each@1.0.3",
				"braces@2.3.2",
				"glob-parent@3.1.0",
				"inherits@2.0.3",
				"is-binary-path@1.0.1",
				"is-glob@4.0.1",
				"normalize-path@3.0.0",
				"path-is-absolute@1.0.1",
				"readdirp@2.2.1",
				"upath@1.1.2",
			},
		},
		{
			ID: "chrome-trace-event@1.0.0",
			DependsOn: []string{
				"tslib@1.9.3",
			},
		},
		{
			ID: "cidr-regex@2.0.10",
			DependsOn: []string{
				"ip-regex@2.1.0",
			},
		},
		{
			ID: "cipher-base@1.0.4",
			DependsOn: []string{
				"inherits@2.0.3",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "class-utils@0.3.6",
			DependsOn: []string{
				"arr-union@3.1.0",
				"define-property@0.2.5",
				"isobject@3.0.1",
				"static-extend@0.1.2",
			},
		},
		{
			ID: "clean-css@4.2.1",
			DependsOn: []string{
				"source-map@0.6.1",
			},
		},
		{
			ID: "clean-webpack-plugin@0.1.19",
			DependsOn: []string{
				"rimraf@2.6.3",
			},
		},
		{
			ID: "cli-columns@3.1.2",
			DependsOn: []string{
				"string-width@2.1.1",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID: "cli-cursor@1.0.2",
			DependsOn: []string{
				"restore-cursor@1.0.1",
			},
		},
		{
			ID: "cli-cursor@2.1.0",
			DependsOn: []string{
				"restore-cursor@2.0.0",
			},
		},
		{
			ID: "cli-table3@0.5.1",
			DependsOn: []string{
				"object-assign@4.1.1",
				"string-width@2.1.1",
			},
		},
		{
			ID: "cli-truncate@0.2.1",
			DependsOn: []string{
				"slice-ansi@0.0.4",
				"string-width@1.0.2",
			},
		},
		{
			ID: "cliui@3.2.0",
			DependsOn: []string{
				"string-width@1.0.2",
				"strip-ansi@3.0.1",
				"wrap-ansi@2.1.0",
			},
		},
		{
			ID: "cliui@4.1.0",
			DependsOn: []string{
				"string-width@2.1.1",
				"strip-ansi@4.0.0",
				"wrap-ansi@2.1.0",
			},
		},
		{
			ID: "clone-deep@0.2.4",
			DependsOn: []string{
				"for-own@0.1.5",
				"is-plain-object@2.0.4",
				"kind-of@3.2.2",
				"lazy-cache@1.0.4",
				"shallow-clone@0.1.2",
			},
		},
		{
			ID: "cmd-shim@2.0.2",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"mkdirp@0.5.1",
			},
		},
		{
			ID: "coa@2.0.2",
			DependsOn: []string{
				"@types/q@1.5.2",
				"chalk@2.4.2",
				"q@1.5.1",
			},
		},
		{
			ID: "collection-visit@1.0.0",
			DependsOn: []string{
				"map-visit@1.0.0",
				"object-visit@1.0.1",
			},
		},
		{
			ID: "color-convert@1.9.3",
			DependsOn: []string{
				"color-name@1.1.3",
			},
		},
		{
			ID: "columnify@1.5.4",
			DependsOn: []string{
				"strip-ansi@3.0.1",
				"wcwidth@1.0.1",
			},
		},
		{
			ID: "combined-stream@1.0.8",
			DependsOn: []string{
				"delayed-stream@1.0.0",
			},
		},
		{
			ID: "compressible@2.0.17",
			DependsOn: []string{
				"mime-db@1.40.0",
			},
		},
		{
			ID: "compression@1.7.4",
			DependsOn: []string{
				"accepts@1.3.7",
				"bytes@3.0.0",
				"compressible@2.0.17",
				"debug@2.6.9",
				"on-headers@1.0.2",
				"safe-buffer@5.1.2",
				"vary@1.1.2",
			},
		},
		{
			ID: "concat-stream@1.6.2",
			DependsOn: []string{
				"buffer-from@1.1.1",
				"inherits@2.0.3",
				"readable-stream@2.3.6",
				"typedarray@0.0.6",
			},
		},
		{
			ID: "config-chain@1.1.12",
			DependsOn: []string{
				"ini@1.3.5",
				"proto-list@1.2.4",
			},
		},
		{
			ID: "configstore@3.1.2",
			DependsOn: []string{
				"dot-prop@4.2.0",
				"graceful-fs@4.1.15",
				"make-dir@1.3.0",
				"unique-string@1.0.0",
				"write-file-atomic@2.4.2",
				"xdg-basedir@3.0.0",
			},
		},
		{
			ID: "console-browserify@1.1.0",
			DependsOn: []string{
				"date-now@0.1.4",
			},
		},
		{
			ID: "convert-source-map@1.6.0",
			DependsOn: []string{
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "copy-concurrently@1.0.5",
			DependsOn: []string{
				"aproba@1.2.0",
				"fs-write-stream-atomic@1.0.10",
				"iferr@0.1.5",
				"mkdirp@0.5.1",
				"rimraf@2.6.3",
				"run-queue@1.0.3",
			},
		},
		{
			ID: "copy-to-clipboard@3.2.0",
			DependsOn: []string{
				"toggle-selection@1.0.6",
			},
		},
		{
			ID: "copy-webpack-plugin@4.6.0",
			DependsOn: []string{
				"cacache@10.0.4",
				"find-cache-dir@1.0.0",
				"globby@7.1.1",
				"is-glob@4.0.1",
				"loader-utils@1.2.3",
				"minimatch@3.0.4",
				"p-limit@1.3.0",
				"serialize-javascript@1.7.0",
			},
		},
		{
			ID: "core-js-compat@3.0.1",
			DependsOn: []string{
				"browserslist@4.6.0",
				"core-js@3.0.1",
				"core-js-pure@3.0.1",
				"semver@6.0.0",
			},
		},
		{
			ID: "cosmiconfig@4.0.0",
			DependsOn: []string{
				"is-directory@0.3.1",
				"js-yaml@3.13.1",
				"parse-json@4.0.0",
				"require-from-string@2.0.2",
			},
		},
		{
			ID: "cosmiconfig@5.2.1",
			DependsOn: []string{
				"import-fresh@2.0.0",
				"is-directory@0.3.1",
				"js-yaml@3.13.1",
				"parse-json@4.0.0",
			},
		},
		{
			ID: "create-ecdh@4.0.3",
			DependsOn: []string{
				"bn.js@4.11.8",
				"elliptic@6.4.1",
			},
		},
		{
			ID: "create-error-class@3.0.2",
			DependsOn: []string{
				"capture-stack-trace@1.0.1",
			},
		},
		{
			ID: "create-hash@1.2.0",
			DependsOn: []string{
				"cipher-base@1.0.4",
				"inherits@2.0.3",
				"md5.js@1.3.5",
				"ripemd160@2.0.2",
				"sha.js@2.4.11",
			},
		},
		{
			ID: "create-hmac@1.1.7",
			DependsOn: []string{
				"cipher-base@1.0.4",
				"create-hash@1.2.0",
				"inherits@2.0.3",
				"ripemd160@2.0.2",
				"safe-buffer@5.1.2",
				"sha.js@2.4.11",
			},
		},
		{
			ID: "create-react-class@15.6.3",
			DependsOn: []string{
				"fbjs@0.8.17",
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
			},
		},
		{
			ID: "create-react-context@0.2.2",
			DependsOn: []string{
				"fbjs@0.8.17",
				"gud@1.0.0",
			},
		},
		{
			ID: "create-react-context@0.2.3",
			DependsOn: []string{
				"fbjs@0.8.17",
				"gud@1.0.0",
			},
		},
		{
			ID: "cross-spawn@6.0.5",
			DependsOn: []string{
				"nice-try@1.0.5",
				"path-key@2.0.1",
				"semver@5.7.0",
				"shebang-command@1.2.0",
				"which@1.3.1",
			},
		},
		{
			ID: "cross-spawn@4.0.2",
			DependsOn: []string{
				"lru-cache@4.1.5",
				"which@1.3.1",
			},
		},
		{
			ID: "cross-spawn@5.1.0",
			DependsOn: []string{
				"lru-cache@4.1.5",
				"shebang-command@1.2.0",
				"which@1.3.1",
			},
		},
		{
			ID: "crypto-browserify@3.12.0",
			DependsOn: []string{
				"browserify-cipher@1.0.1",
				"browserify-sign@4.0.4",
				"create-ecdh@4.0.3",
				"create-hash@1.2.0",
				"create-hmac@1.1.7",
				"diffie-hellman@5.0.3",
				"inherits@2.0.3",
				"pbkdf2@3.0.17",
				"public-encrypt@4.0.3",
				"randombytes@2.1.0",
				"randomfill@1.0.4",
			},
		},
		{
			ID: "css-loader@1.0.1",
			DependsOn: []string{
				"babel-code-frame@6.26.0",
				"css-selector-tokenizer@0.7.1",
				"icss-utils@2.1.0",
				"loader-utils@1.2.3",
				"lodash@4.17.11",
				"postcss@6.0.23",
				"postcss-modules-extract-imports@1.2.1",
				"postcss-modules-local-by-default@1.2.0",
				"postcss-modules-scope@1.1.0",
				"postcss-modules-values@1.3.0",
				"postcss-value-parser@3.3.1",
				"source-list-map@2.0.1",
			},
		},
		{
			ID: "css-select@1.2.0",
			DependsOn: []string{
				"boolbase@1.0.0",
				"css-what@2.1.3",
				"domutils@1.5.1",
				"nth-check@1.0.2",
			},
		},
		{
			ID: "css-select@2.0.2",
			DependsOn: []string{
				"boolbase@1.0.0",
				"css-what@2.1.3",
				"domutils@1.7.0",
				"nth-check@1.0.2",
			},
		},
		{
			ID: "css-selector-tokenizer@0.7.1",
			DependsOn: []string{
				"cssesc@0.1.0",
				"fastparse@1.1.2",
				"regexpu-core@1.0.0",
			},
		},
		{
			ID: "css-to-react-native@2.3.1",
			DependsOn: []string{
				"camelize@1.0.0",
				"css-color-keywords@1.0.0",
				"postcss-value-parser@3.3.1",
			},
		},
		{
			ID: "css-tree@1.0.0-alpha.28",
			DependsOn: []string{
				"mdn-data@1.1.4",
				"source-map@0.5.7",
			},
		},
		{
			ID: "css-tree@1.0.0-alpha.29",
			DependsOn: []string{
				"mdn-data@1.1.4",
				"source-map@0.5.7",
			},
		},
		{
			ID: "css-vendor@0.3.8",
			DependsOn: []string{
				"is-in-browser@1.1.3",
			},
		},
		{
			ID: "csso@3.5.1",
			DependsOn: []string{
				"css-tree@1.0.0-alpha.29",
			},
		},
		{
			ID: "cssstyle@1.2.2",
			DependsOn: []string{
				"cssom@0.3.6",
			},
		},
		{
			ID: "dashdash@1.14.1",
			DependsOn: []string{
				"assert-plus@1.0.0",
			},
		},
		{
			ID: "data-urls@1.1.0",
			DependsOn: []string{
				"abab@2.0.0",
				"whatwg-mimetype@2.3.0",
				"whatwg-url@7.0.0",
			},
		},
		{
			ID: "debug@2.6.9",
			DependsOn: []string{
				"ms@2.0.0",
			},
		},
		{
			ID: "debug@3.1.0",
			DependsOn: []string{
				"ms@2.0.0",
			},
		},
		{
			ID: "debug@3.2.6",
			DependsOn: []string{
				"ms@2.1.1",
			},
		},
		{
			ID: "debug@4.1.1",
			DependsOn: []string{
				"ms@2.1.1",
			},
		},
		{
			ID: "decompress-response@3.3.0",
			DependsOn: []string{
				"mimic-response@1.0.1",
			},
		},
		{
			ID: "default-gateway@4.2.0",
			DependsOn: []string{
				"execa@1.0.0",
				"ip-regex@2.1.0",
			},
		},
		{
			ID: "default-require-extensions@1.0.0",
			DependsOn: []string{
				"strip-bom@2.0.0",
			},
		},
		{
			ID: "defaults@1.0.3",
			DependsOn: []string{
				"clone@1.0.4",
			},
		},
		{
			ID: "define-properties@1.1.3",
			DependsOn: []string{
				"object-keys@1.1.1",
			},
		},
		{
			ID: "define-property@0.2.5",
			DependsOn: []string{
				"is-descriptor@0.1.6",
			},
		},
		{
			ID: "define-property@1.0.0",
			DependsOn: []string{
				"is-descriptor@1.0.2",
			},
		},
		{
			ID: "define-property@2.0.2",
			DependsOn: []string{
				"is-descriptor@1.0.2",
				"isobject@3.0.1",
			},
		},
		{
			ID: "del@3.0.0",
			DependsOn: []string{
				"globby@6.1.0",
				"is-path-cwd@1.0.0",
				"is-path-in-cwd@1.0.1",
				"p-map@1.2.0",
				"pify@3.0.0",
				"rimraf@2.6.3",
			},
		},
		{
			ID: "del@4.1.1",
			DependsOn: []string{
				"@types/glob@7.1.1",
				"globby@6.1.0",
				"is-path-cwd@2.1.0",
				"is-path-in-cwd@2.1.0",
				"p-map@2.1.0",
				"pify@4.0.1",
				"rimraf@2.6.3",
			},
		},
		{
			ID: "des.js@1.0.0",
			DependsOn: []string{
				"inherits@2.0.3",
				"minimalistic-assert@1.0.1",
			},
		},
		{
			ID: "detect-indent@4.0.0",
			DependsOn: []string{
				"repeating@2.0.1",
			},
		},
		{
			ID: "detect-port-alt@1.1.6",
			DependsOn: []string{
				"address@1.1.0",
				"debug@2.6.9",
			},
		},
		{
			ID: "detect-port@1.3.0",
			DependsOn: []string{
				"address@1.1.0",
				"debug@2.6.9",
			},
		},
		{
			ID: "dezalgo@1.0.3",
			DependsOn: []string{
				"asap@2.0.6",
				"wrappy@1.0.2",
			},
		},
		{
			ID: "diffie-hellman@5.0.3",
			DependsOn: []string{
				"bn.js@4.11.8",
				"miller-rabin@4.0.1",
				"randombytes@2.1.0",
			},
		},
		{
			ID: "dir-glob@2.2.2",
			DependsOn: []string{
				"path-type@3.0.0",
			},
		},
		{
			ID: "dns-packet@1.3.1",
			DependsOn: []string{
				"ip@1.1.5",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "dns-txt@2.0.2",
			DependsOn: []string{
				"buffer-indexof@1.1.1",
			},
		},
		{
			ID: "doctrine@1.5.0",
			DependsOn: []string{
				"esutils@2.0.2",
				"isarray@1.0.0",
			},
		},
		{
			ID: "doctrine@2.1.0",
			DependsOn: []string{
				"esutils@2.0.2",
			},
		},
		{
			ID: "doctrine@3.0.0",
			DependsOn: []string{
				"esutils@2.0.2",
			},
		},
		{
			ID: "dom-converter@0.2.0",
			DependsOn: []string{
				"utila@0.4.0",
			},
		},
		{
			ID: "dom-helpers@3.4.0",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
			},
		},
		{
			ID: "dom-serializer@0.1.1",
			DependsOn: []string{
				"domelementtype@1.3.1",
				"entities@1.1.2",
			},
		},
		{
			ID: "domexception@1.0.1",
			DependsOn: []string{
				"webidl-conversions@4.0.2",
			},
		},
		{
			ID: "domhandler@2.4.2",
			DependsOn: []string{
				"domelementtype@1.3.1",
			},
		},
		{
			ID: "domutils@1.5.1",
			DependsOn: []string{
				"dom-serializer@0.1.1",
				"domelementtype@1.3.1",
			},
		},
		{
			ID: "domutils@1.7.0",
			DependsOn: []string{
				"dom-serializer@0.1.1",
				"domelementtype@1.3.1",
			},
		},
		{
			ID: "dot-prop@4.2.0",
			DependsOn: []string{
				"is-obj@1.0.1",
			},
		},
		{
			ID: "dotenv-defaults@1.0.2",
			DependsOn: []string{
				"dotenv@6.2.0",
			},
		},
		{
			ID: "dotenv-webpack@1.7.0",
			DependsOn: []string{
				"dotenv-defaults@1.0.2",
			},
		},
		{
			ID: "duplexer2@0.1.4",
			DependsOn: []string{
				"readable-stream@2.3.6",
			},
		},
		{
			ID: "duplexify@3.7.1",
			DependsOn: []string{
				"end-of-stream@1.4.1",
				"inherits@2.0.3",
				"readable-stream@2.3.6",
				"stream-shift@1.0.0",
			},
		},
		{
			ID: "ecc-jsbn@0.1.2",
			DependsOn: []string{
				"jsbn@0.1.1",
				"safer-buffer@2.1.2",
			},
		},
		{
			ID: "elliptic@6.4.1",
			DependsOn: []string{
				"bn.js@4.11.8",
				"brorand@1.1.0",
				"hash.js@1.1.7",
				"hmac-drbg@1.0.1",
				"inherits@2.0.3",
				"minimalistic-assert@1.0.1",
				"minimalistic-crypto-utils@1.0.1",
			},
		},
		{
			ID: "encoding@0.1.12",
			DependsOn: []string{
				"iconv-lite@0.4.24",
			},
		},
		{
			ID: "end-of-stream@1.4.1",
			DependsOn: []string{
				"once@1.4.0",
			},
		},
		{
			ID: "engine.io-client@3.3.2",
			DependsOn: []string{
				"component-emitter@1.2.1",
				"component-inherit@0.0.3",
				"debug@3.1.0",
				"engine.io-parser@2.1.3",
				"has-cors@1.1.0",
				"indexof@0.0.1",
				"parseqs@0.0.5",
				"parseuri@0.0.5",
				"ws@6.1.4",
				"xmlhttprequest-ssl@1.5.5",
				"yeast@0.1.2",
			},
		},
		{
			ID: "engine.io-parser@2.1.3",
			DependsOn: []string{
				"after@0.8.2",
				"arraybuffer.slice@0.0.7",
				"base64-arraybuffer@0.1.5",
				"blob@0.0.5",
				"has-binary2@1.0.3",
			},
		},
		{
			ID: "engine.io@3.3.2",
			DependsOn: []string{
				"accepts@1.3.7",
				"base64id@1.0.0",
				"cookie@0.3.1",
				"debug@3.1.0",
				"engine.io-parser@2.1.3",
				"ws@6.1.4",
			},
		},
		{
			ID: "enhanced-resolve@4.1.0",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"memory-fs@0.4.1",
				"tapable@1.1.3",
			},
		},
		{
			ID: "enzyme-adapter-react-16@1.13.0",
			DependsOn: []string{
				"enzyme-adapter-utils@1.12.0",
				"object.assign@4.1.0",
				"object.values@1.1.0",
				"prop-types@15.7.2",
				"react-is@16.8.6",
				"react-test-renderer@16.8.6",
				"semver@5.7.0",
			},
		},
		{
			ID: "enzyme-adapter-utils@1.12.0",
			DependsOn: []string{
				"airbnb-prop-types@2.13.2",
				"function.prototype.name@1.1.0",
				"object.assign@4.1.0",
				"object.fromentries@2.0.0",
				"prop-types@15.7.2",
				"semver@5.7.0",
			},
		},
		{
			ID: "enzyme@3.9.0",
			DependsOn: []string{
				"array.prototype.flat@1.2.1",
				"cheerio@1.0.0-rc.3",
				"function.prototype.name@1.1.0",
				"has@1.0.3",
				"html-element-map@1.0.1",
				"is-boolean-object@1.0.0",
				"is-callable@1.1.4",
				"is-number-object@1.0.3",
				"is-regex@1.0.4",
				"is-string@1.0.4",
				"is-subset@0.1.1",
				"lodash.escape@4.0.1",
				"lodash.isequal@4.5.0",
				"object-inspect@1.6.0",
				"object-is@1.0.1",
				"object.assign@4.1.0",
				"object.entries@1.1.0",
				"object.values@1.1.0",
				"raf@3.4.1",
				"rst-selector-parser@2.2.3",
				"string.prototype.trim@1.1.2",
			},
		},
		{
			ID: "errno@0.1.7",
			DependsOn: []string{
				"prr@1.0.1",
			},
		},
		{
			ID: "error-ex@1.3.2",
			DependsOn: []string{
				"is-arrayish@0.2.1",
			},
		},
		{
			ID: "es-abstract@1.13.0",
			DependsOn: []string{
				"es-to-primitive@1.2.0",
				"function-bind@1.1.1",
				"has@1.0.3",
				"is-callable@1.1.4",
				"is-regex@1.0.4",
				"object-keys@1.1.1",
			},
		},
		{
			ID: "es-to-primitive@1.2.0",
			DependsOn: []string{
				"is-callable@1.1.4",
				"is-date-object@1.0.1",
				"is-symbol@1.0.2",
			},
		},
		{
			ID: "es6-promise-promise@1.0.0",
			DependsOn: []string{
				"es6-promise@3.3.1",
			},
		},
		{
			ID: "es6-promisify@5.0.0",
			DependsOn: []string{
				"es6-promise@4.2.6",
			},
		},
		{
			ID: "escodegen@1.11.1",
			DependsOn: []string{
				"esprima@3.1.3",
				"estraverse@4.2.0",
				"esutils@2.0.2",
				"optionator@0.8.2",
			},
		},
		{
			ID: "eslint-config-airbnb-base@13.1.0",
			DependsOn: []string{
				"eslint-restricted-globals@0.1.1",
				"object.assign@4.1.0",
				"object.entries@1.1.0",
			},
		},
		{
			ID: "eslint-config-airbnb@17.1.0",
			DependsOn: []string{
				"eslint-config-airbnb-base@13.1.0",
				"object.assign@4.1.0",
				"object.entries@1.1.0",
			},
		},
		{
			ID: "eslint-import-resolver-node@0.3.2",
			DependsOn: []string{
				"debug@2.6.9",
				"resolve@1.10.1",
			},
		},
		{
			ID: "eslint-loader@2.1.2",
			DependsOn: []string{
				"loader-fs-cache@1.0.2",
				"loader-utils@1.2.3",
				"object-assign@4.1.1",
				"object-hash@1.3.1",
				"rimraf@2.6.3",
			},
		},
		{
			ID: "eslint-module-utils@2.4.0",
			DependsOn: []string{
				"debug@2.6.9",
				"pkg-dir@2.0.0",
			},
		},
		{
			ID: "eslint-plugin-import@2.17.2",
			DependsOn: []string{
				"array-includes@3.0.3",
				"contains-path@0.1.0",
				"debug@2.6.9",
				"doctrine@1.5.0",
				"eslint-import-resolver-node@0.3.2",
				"eslint-module-utils@2.4.0",
				"has@1.0.3",
				"lodash@4.17.11",
				"minimatch@3.0.4",
				"read-pkg-up@2.0.0",
				"resolve@1.10.1",
			},
		},
		{
			ID: "eslint-plugin-jsx-a11y@6.2.1",
			DependsOn: []string{
				"aria-query@3.0.0",
				"array-includes@3.0.3",
				"ast-types-flow@0.0.7",
				"axobject-query@2.0.2",
				"damerau-levenshtein@1.0.5",
				"emoji-regex@7.0.3",
				"has@1.0.3",
				"jsx-ast-utils@2.1.0",
			},
		},
		{
			ID: "eslint-plugin-react@7.13.0",
			DependsOn: []string{
				"array-includes@3.0.3",
				"doctrine@2.1.0",
				"has@1.0.3",
				"jsx-ast-utils@2.1.0",
				"object.fromentries@2.0.0",
				"prop-types@15.7.2",
				"resolve@1.10.1",
			},
		},
		{
			ID: "eslint-scope@3.7.1",
			DependsOn: []string{
				"esrecurse@4.2.1",
				"estraverse@4.2.0",
			},
		},
		{
			ID: "eslint-scope@4.0.3",
			DependsOn: []string{
				"esrecurse@4.2.1",
				"estraverse@4.2.0",
			},
		},
		{
			ID: "eslint@5.16.0",
			DependsOn: []string{
				"@babel/code-frame@7.0.0",
				"ajv@6.10.0",
				"chalk@2.4.2",
				"cross-spawn@6.0.5",
				"debug@4.1.1",
				"doctrine@3.0.0",
				"eslint-scope@4.0.3",
				"eslint-utils@1.3.1",
				"eslint-visitor-keys@1.0.0",
				"espree@5.0.1",
				"esquery@1.0.1",
				"esutils@2.0.2",
				"file-entry-cache@5.0.1",
				"functional-red-black-tree@1.0.1",
				"glob@7.1.4",
				"globals@11.12.0",
				"ignore@4.0.6",
				"import-fresh@3.0.0",
				"imurmurhash@0.1.4",
				"inquirer@6.3.1",
				"js-yaml@3.13.1",
				"json-stable-stringify-without-jsonify@1.0.1",
				"levn@0.3.0",
				"lodash@4.17.11",
				"minimatch@3.0.4",
				"mkdirp@0.5.1",
				"natural-compare@1.4.0",
				"optionator@0.8.2",
				"path-is-inside@1.0.2",
				"progress@2.0.3",
				"regexpp@2.0.1",
				"semver@5.7.0",
				"strip-ansi@4.0.0",
				"strip-json-comments@2.0.1",
				"table@5.3.3",
				"text-table@0.2.0",
			},
		},
		{
			ID: "espree@5.0.1",
			DependsOn: []string{
				"acorn@6.1.1",
				"acorn-jsx@5.0.1",
				"eslint-visitor-keys@1.0.0",
			},
		},
		{
			ID: "esquery@1.0.1",
			DependsOn: []string{
				"estraverse@4.2.0",
			},
		},
		{
			ID: "esrecurse@4.2.1",
			DependsOn: []string{
				"estraverse@4.2.0",
			},
		},
		{
			ID: "eventsource@0.1.6",
			DependsOn: []string{
				"original@1.0.2",
			},
		},
		{
			ID: "eventsource@1.0.7",
			DependsOn: []string{
				"original@1.0.2",
			},
		},
		{
			ID: "evp_bytestokey@1.0.3",
			DependsOn: []string{
				"md5.js@1.3.5",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "exec-sh@0.2.2",
			DependsOn: []string{
				"merge@1.2.1",
			},
		},
		{
			ID: "execa@0.7.0",
			DependsOn: []string{
				"cross-spawn@5.1.0",
				"get-stream@3.0.0",
				"is-stream@1.1.0",
				"npm-run-path@2.0.2",
				"p-finally@1.0.0",
				"signal-exit@3.0.2",
				"strip-eof@1.0.0",
			},
		},
		{
			ID: "execa@0.9.0",
			DependsOn: []string{
				"cross-spawn@5.1.0",
				"get-stream@3.0.0",
				"is-stream@1.1.0",
				"npm-run-path@2.0.2",
				"p-finally@1.0.0",
				"signal-exit@3.0.2",
				"strip-eof@1.0.0",
			},
		},
		{
			ID: "execa@1.0.0",
			DependsOn: []string{
				"cross-spawn@6.0.5",
				"get-stream@4.1.0",
				"is-stream@1.1.0",
				"npm-run-path@2.0.2",
				"p-finally@1.0.0",
				"signal-exit@3.0.2",
				"strip-eof@1.0.0",
			},
		},
		{
			ID: "expand-brackets@0.1.5",
			DependsOn: []string{
				"is-posix-bracket@0.1.1",
			},
		},
		{
			ID: "expand-brackets@2.1.4",
			DependsOn: []string{
				"debug@2.6.9",
				"define-property@0.2.5",
				"extend-shallow@2.0.1",
				"posix-character-classes@0.1.1",
				"regex-not@1.0.2",
				"snapdragon@0.8.2",
				"to-regex@3.0.2",
			},
		},
		{
			ID: "expand-range@1.8.2",
			DependsOn: []string{
				"fill-range@2.2.4",
			},
		},
		{
			ID: "expand-tilde@2.0.2",
			DependsOn: []string{
				"homedir-polyfill@1.0.3",
			},
		},
		{
			ID: "expect@23.6.0",
			DependsOn: []string{
				"ansi-styles@3.2.1",
				"jest-diff@23.6.0",
				"jest-get-type@22.4.3",
				"jest-matcher-utils@23.6.0",
				"jest-message-util@23.4.0",
				"jest-regex-util@23.3.0",
			},
		},
		{
			ID: "express@4.16.4",
			DependsOn: []string{
				"accepts@1.3.7",
				"array-flatten@1.1.1",
				"body-parser@1.18.3",
				"content-disposition@0.5.2",
				"content-type@1.0.4",
				"cookie@0.3.1",
				"cookie-signature@1.0.6",
				"debug@2.6.9",
				"depd@1.1.2",
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"etag@1.8.1",
				"finalhandler@1.1.1",
				"fresh@0.5.2",
				"merge-descriptors@1.0.1",
				"methods@1.1.2",
				"on-finished@2.3.0",
				"parseurl@1.3.3",
				"path-to-regexp@0.1.7",
				"proxy-addr@2.0.5",
				"qs@6.5.2",
				"range-parser@1.2.1",
				"safe-buffer@5.1.2",
				"send@0.16.2",
				"serve-static@1.13.2",
				"setprototypeof@1.1.0",
				"statuses@1.4.0",
				"type-is@1.6.18",
				"utils-merge@1.0.1",
				"vary@1.1.2",
			},
		},
		{
			ID: "extend-shallow@2.0.1",
			DependsOn: []string{
				"is-extendable@0.1.1",
			},
		},
		{
			ID: "extend-shallow@3.0.2",
			DependsOn: []string{
				"assign-symbols@1.0.0",
				"is-extendable@1.0.1",
			},
		},
		{
			ID: "external-editor@3.0.3",
			DependsOn: []string{
				"chardet@0.7.0",
				"iconv-lite@0.4.24",
				"tmp@0.0.33",
			},
		},
		{
			ID: "extglob@0.3.2",
			DependsOn: []string{
				"is-extglob@1.0.0",
			},
		},
		{
			ID: "extglob@2.0.4",
			DependsOn: []string{
				"array-unique@0.3.2",
				"define-property@1.0.0",
				"expand-brackets@2.1.4",
				"extend-shallow@2.0.1",
				"fragment-cache@0.2.1",
				"regex-not@1.0.2",
				"snapdragon@0.8.2",
				"to-regex@3.0.2",
			},
		},
		{
			ID: "extract-text-webpack-plugin@4.0.0-beta.0",
			DependsOn: []string{
				"async@2.6.2",
				"loader-utils@1.2.3",
				"schema-utils@0.4.7",
				"webpack-sources@1.3.0",
			},
		},
		{
			ID: "fast-glob@2.2.6",
			DependsOn: []string{
				"@mrmlnc/readdir-enhanced@2.2.1",
				"@nodelib/fs.stat@1.1.3",
				"glob-parent@3.1.0",
				"is-glob@4.0.1",
				"merge2@1.2.3",
				"micromatch@3.1.10",
			},
		},
		{
			ID: "faye-websocket@0.10.0",
			DependsOn: []string{
				"websocket-driver@0.7.0",
			},
		},
		{
			ID: "faye-websocket@0.11.1",
			DependsOn: []string{
				"websocket-driver@0.7.0",
			},
		},
		{
			ID: "fb-watchman@2.0.0",
			DependsOn: []string{
				"bser@2.0.0",
			},
		},
		{
			ID: "fbjs@0.8.17",
			DependsOn: []string{
				"core-js@1.2.7",
				"isomorphic-fetch@2.2.1",
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"promise@7.3.1",
				"setimmediate@1.0.5",
				"ua-parser-js@0.7.19",
			},
		},
		{
			ID: "figures@1.7.0",
			DependsOn: []string{
				"escape-string-regexp@1.0.5",
				"object-assign@4.1.1",
			},
		},
		{
			ID: "figures@2.0.0",
			DependsOn: []string{
				"escape-string-regexp@1.0.5",
			},
		},
		{
			ID: "file-entry-cache@5.0.1",
			DependsOn: []string{
				"flat-cache@2.0.1",
			},
		},
		{
			ID: "file-loader@1.1.11",
			DependsOn: []string{
				"loader-utils@1.2.3",
				"schema-utils@0.4.7",
			},
		},
		{
			ID: "file-loader@2.0.0",
			DependsOn: []string{
				"loader-utils@1.2.3",
				"schema-utils@1.0.0",
			},
		},
		{
			ID: "file-selector@0.1.11",
			DependsOn: []string{
				"tslib@1.9.3",
			},
		},
		{
			ID: "file-system-cache@1.0.5",
			DependsOn: []string{
				"bluebird@3.5.4",
				"fs-extra@0.30.0",
				"ramda@0.21.0",
			},
		},
		{
			ID: "fileset@2.0.3",
			DependsOn: []string{
				"glob@7.1.4",
				"minimatch@3.0.4",
			},
		},
		{
			ID: "fill-range@2.2.4",
			DependsOn: []string{
				"is-number@2.1.0",
				"isobject@2.1.0",
				"randomatic@3.1.1",
				"repeat-element@1.1.3",
				"repeat-string@1.6.1",
			},
		},
		{
			ID: "fill-range@4.0.0",
			DependsOn: []string{
				"extend-shallow@2.0.1",
				"is-number@3.0.0",
				"repeat-string@1.6.1",
				"to-regex-range@2.1.1",
			},
		},
		{
			ID: "finalhandler@1.1.1",
			DependsOn: []string{
				"debug@2.6.9",
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"on-finished@2.3.0",
				"parseurl@1.3.3",
				"statuses@1.4.0",
				"unpipe@1.0.0",
			},
		},
		{
			ID: "find-cache-dir@0.1.1",
			DependsOn: []string{
				"commondir@1.0.1",
				"mkdirp@0.5.1",
				"pkg-dir@1.0.0",
			},
		},
		{
			ID: "find-cache-dir@1.0.0",
			DependsOn: []string{
				"commondir@1.0.1",
				"make-dir@1.3.0",
				"pkg-dir@2.0.0",
			},
		},
		{
			ID: "find-cache-dir@2.1.0",
			DependsOn: []string{
				"commondir@1.0.1",
				"make-dir@2.1.0",
				"pkg-dir@3.0.0",
			},
		},
		{
			ID: "find-up@3.0.0",
			DependsOn: []string{
				"locate-path@3.0.0",
			},
		},
		{
			ID: "find-up@1.1.2",
			DependsOn: []string{
				"path-exists@2.1.0",
				"pinkie-promise@2.0.1",
			},
		},
		{
			ID: "find-up@2.1.0",
			DependsOn: []string{
				"locate-path@2.0.0",
			},
		},
		{
			ID: "findup-sync@2.0.0",
			DependsOn: []string{
				"detect-file@1.0.0",
				"is-glob@3.1.0",
				"micromatch@3.1.10",
				"resolve-dir@1.0.1",
			},
		},
		{
			ID: "flat-cache@2.0.1",
			DependsOn: []string{
				"flatted@2.0.0",
				"rimraf@2.6.3",
				"write@1.0.3",
			},
		},
		{
			ID: "flow-typed@2.5.1",
			DependsOn: []string{
				"@octokit/rest@15.18.1",
				"babel-polyfill@6.26.0",
				"colors@1.3.3",
				"fs-extra@5.0.0",
				"glob@7.1.4",
				"got@7.1.0",
				"md5@2.2.1",
				"mkdirp@0.5.1",
				"rimraf@2.6.3",
				"semver@5.7.0",
				"table@4.0.3",
				"through@2.3.8",
				"unzipper@0.8.14",
				"which@1.3.1",
				"yargs@4.8.1",
			},
		},
		{
			ID: "flush-write-stream@1.1.1",
			DependsOn: []string{
				"inherits@2.0.3",
				"readable-stream@2.3.6",
			},
		},
		{
			ID: "follow-redirects@1.7.0",
			DependsOn: []string{
				"debug@3.2.6",
			},
		},
		{
			ID: "for-own@0.1.5",
			DependsOn: []string{
				"for-in@1.0.2",
			},
		},
		{
			ID: "form-data@2.3.3",
			DependsOn: []string{
				"asynckit@0.4.0",
				"combined-stream@1.0.8",
				"mime-types@2.1.24",
			},
		},
		{
			ID: "formik@1.5.1",
			DependsOn: []string{
				"create-react-context@0.2.3",
				"deepmerge@2.2.1",
				"hoist-non-react-statics@2.5.5",
				"lodash@4.17.11",
				"lodash-es@4.17.11",
				"prop-types@15.7.2",
				"react-fast-compare@2.0.4",
				"tiny-warning@1.0.2",
				"tslib@1.9.3",
			},
		},
		{
			ID: "fragment-cache@0.2.1",
			DependsOn: []string{
				"map-cache@0.2.2",
			},
		},
		{
			ID: "from2@1.3.0",
			DependsOn: []string{
				"inherits@2.0.3",
				"readable-stream@1.1.14",
			},
		},
		{
			ID: "from2@2.3.0",
			DependsOn: []string{
				"inherits@2.0.3",
				"readable-stream@2.3.6",
			},
		},
		{
			ID: "fs-extra@0.30.0",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"jsonfile@2.4.0",
				"klaw@1.3.1",
				"path-is-absolute@1.0.1",
				"rimraf@2.6.3",
			},
		},
		{
			ID: "fs-extra@5.0.0",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"jsonfile@4.0.0",
				"universalify@0.1.2",
			},
		},
		{
			ID: "fs-extra@7.0.1",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"jsonfile@4.0.0",
				"universalify@0.1.2",
			},
		},
		{
			ID: "fs-minipass@1.2.5",
			DependsOn: []string{
				"minipass@2.3.5",
			},
		},
		{
			ID: "fs-vacuum@1.2.10",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"path-is-inside@1.0.2",
				"rimraf@2.6.3",
			},
		},
		{
			ID: "fs-write-stream-atomic@1.0.10",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"iferr@0.1.5",
				"imurmurhash@0.1.4",
				"readable-stream@2.3.6",
			},
		},
		{
			ID: "fsevents@1.2.9",
			DependsOn: []string{
				"nan@2.13.2",
				"node-pre-gyp@0.12.0",
			},
		},
		{
			ID: "fstream@1.0.12",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"inherits@2.0.3",
				"mkdirp@0.5.1",
				"rimraf@2.6.3",
			},
		},
		{
			ID: "function.prototype.name@1.1.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"function-bind@1.1.1",
				"is-callable@1.1.4",
			},
		},
		{
			ID: "gauge@2.7.4",
			DependsOn: []string{
				"aproba@1.2.0",
				"console-control-strings@1.1.0",
				"has-unicode@2.0.1",
				"object-assign@4.1.1",
				"signal-exit@3.0.2",
				"string-width@1.0.2",
				"strip-ansi@3.0.1",
				"wide-align@1.1.3",
			},
		},
		{
			ID: "gentle-fs@2.0.1",
			DependsOn: []string{
				"aproba@1.2.0",
				"fs-vacuum@1.2.10",
				"graceful-fs@4.1.15",
				"iferr@0.1.5",
				"mkdirp@0.5.1",
				"path-is-inside@1.0.2",
				"read-cmd-shim@1.0.1",
				"slide@1.1.6",
			},
		},
		{
			ID: "get-stream@4.1.0",
			DependsOn: []string{
				"pump@3.0.0",
			},
		},
		{
			ID: "getpass@0.1.7",
			DependsOn: []string{
				"assert-plus@1.0.0",
			},
		},
		{
			ID: "glob-base@0.3.0",
			DependsOn: []string{
				"glob-parent@2.0.0",
				"is-glob@2.0.1",
			},
		},
		{
			ID: "glob-parent@2.0.0",
			DependsOn: []string{
				"is-glob@2.0.1",
			},
		},
		{
			ID: "glob-parent@3.1.0",
			DependsOn: []string{
				"is-glob@3.1.0",
				"path-dirname@1.0.2",
			},
		},
		{
			ID: "glob@7.1.4",
			DependsOn: []string{
				"fs.realpath@1.0.0",
				"inflight@1.0.6",
				"inherits@2.0.3",
				"minimatch@3.0.4",
				"once@1.4.0",
				"path-is-absolute@1.0.1",
			},
		},
		{
			ID: "global-dirs@0.1.1",
			DependsOn: []string{
				"ini@1.3.5",
			},
		},
		{
			ID: "global-modules@1.0.0",
			DependsOn: []string{
				"global-prefix@1.0.2",
				"is-windows@1.0.2",
				"resolve-dir@1.0.1",
			},
		},
		{
			ID: "global-prefix@1.0.2",
			DependsOn: []string{
				"expand-tilde@2.0.2",
				"homedir-polyfill@1.0.3",
				"ini@1.3.5",
				"is-windows@1.0.2",
				"which@1.3.1",
			},
		},
		{
			ID: "global@4.3.2",
			DependsOn: []string{
				"min-document@2.19.0",
				"process@0.5.2",
			},
		},
		{
			ID: "globalthis@1.0.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"function-bind@1.1.1",
				"object-keys@1.1.1",
			},
		},
		{
			ID: "globby@8.0.1",
			DependsOn: []string{
				"array-union@1.0.2",
				"dir-glob@2.2.2",
				"fast-glob@2.2.6",
				"glob@7.1.4",
				"ignore@3.3.10",
				"pify@3.0.0",
				"slash@1.0.0",
			},
		},
		{
			ID: "globby@6.1.0",
			DependsOn: []string{
				"array-union@1.0.2",
				"glob@7.1.4",
				"object-assign@4.1.1",
				"pify@2.3.0",
				"pinkie-promise@2.0.1",
			},
		},
		{
			ID: "globby@7.1.1",
			DependsOn: []string{
				"array-union@1.0.2",
				"dir-glob@2.2.2",
				"glob@7.1.4",
				"ignore@3.3.10",
				"pify@3.0.0",
				"slash@1.0.0",
			},
		},
		{
			ID: "got@6.7.1",
			DependsOn: []string{
				"create-error-class@3.0.2",
				"duplexer3@0.1.4",
				"get-stream@3.0.0",
				"is-redirect@1.0.0",
				"is-retry-allowed@1.1.0",
				"is-stream@1.1.0",
				"lowercase-keys@1.0.1",
				"safe-buffer@5.1.2",
				"timed-out@4.0.1",
				"unzip-response@2.0.1",
				"url-parse-lax@1.0.0",
			},
		},
		{
			ID: "got@7.1.0",
			DependsOn: []string{
				"decompress-response@3.3.0",
				"duplexer3@0.1.4",
				"get-stream@3.0.0",
				"is-plain-obj@1.1.0",
				"is-retry-allowed@1.1.0",
				"is-stream@1.1.0",
				"isurl@1.0.0",
				"lowercase-keys@1.0.1",
				"p-cancelable@0.3.0",
				"p-timeout@1.2.1",
				"safe-buffer@5.1.2",
				"timed-out@4.0.1",
				"url-parse-lax@1.0.0",
				"url-to-options@1.0.1",
			},
		},
		{
			ID: "gzip-size@5.0.0",
			DependsOn: []string{
				"duplexer@0.1.1",
				"pify@3.0.0",
			},
		},
		{
			ID: "gzip-size@5.1.0",
			DependsOn: []string{
				"duplexer@0.1.1",
				"pify@4.0.1",
			},
		},
		{
			ID: "handlebars@4.1.2",
			DependsOn: []string{
				"neo-async@2.6.1",
				"optimist@0.6.1",
				"source-map@0.6.1",
			},
		},
		{
			ID: "har-validator@5.1.3",
			DependsOn: []string{
				"ajv@6.10.0",
				"har-schema@2.0.0",
			},
		},
		{
			ID: "hard-source-webpack-plugin@0.13.1",
			DependsOn: []string{
				"chalk@2.4.2",
				"find-cache-dir@2.1.0",
				"graceful-fs@4.1.15",
				"lodash@4.17.11",
				"mkdirp@0.5.1",
				"node-object-hash@1.4.2",
				"parse-json@4.0.0",
				"pkg-dir@3.0.0",
				"rimraf@2.6.3",
				"semver@5.7.0",
				"tapable@1.1.3",
				"webpack-sources@1.3.0",
				"write-json-file@2.3.0",
			},
		},
		{
			ID: "has-ansi@2.0.0",
			DependsOn: []string{
				"ansi-regex@2.1.1",
			},
		},
		{
			ID: "has-binary2@1.0.3",
			DependsOn: []string{
				"isarray@2.0.1",
			},
		},
		{
			ID: "has-to-string-tag-x@1.4.1",
			DependsOn: []string{
				"has-symbol-support-x@1.4.2",
			},
		},
		{
			ID: "has-value@0.3.1",
			DependsOn: []string{
				"get-value@2.0.6",
				"has-values@0.1.4",
				"isobject@2.1.0",
			},
		},
		{
			ID: "has-value@1.0.0",
			DependsOn: []string{
				"get-value@2.0.6",
				"has-values@1.0.0",
				"isobject@3.0.1",
			},
		},
		{
			ID: "has-values@1.0.0",
			DependsOn: []string{
				"is-number@3.0.0",
				"kind-of@4.0.0",
			},
		},
		{
			ID: "has@1.0.3",
			DependsOn: []string{
				"function-bind@1.1.1",
			},
		},
		{
			ID: "hash-base@3.0.4",
			DependsOn: []string{
				"inherits@2.0.3",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "hash.js@1.1.7",
			DependsOn: []string{
				"inherits@2.0.3",
				"minimalistic-assert@1.0.1",
			},
		},
		{
			ID: "hast-util-from-parse5@5.0.0",
			DependsOn: []string{
				"ccount@1.0.4",
				"hastscript@5.0.0",
				"property-information@5.1.0",
				"web-namespaces@1.1.3",
				"xtend@4.0.1",
			},
		},
		{
			ID: "hastscript@5.0.0",
			DependsOn: []string{
				"comma-separated-tokens@1.0.7",
				"hast-util-parse-selector@2.2.1",
				"property-information@5.1.0",
				"space-separated-tokens@1.1.4",
			},
		},
		{
			ID: "history@4.9.0",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"loose-envify@1.4.0",
				"resolve-pathname@2.2.0",
				"tiny-invariant@1.0.4",
				"tiny-warning@1.0.2",
				"value-equal@0.4.0",
			},
		},
		{
			ID: "hmac-drbg@1.0.1",
			DependsOn: []string{
				"hash.js@1.1.7",
				"minimalistic-assert@1.0.1",
				"minimalistic-crypto-utils@1.0.1",
			},
		},
		{
			ID: "hoist-non-react-statics@3.3.0",
			DependsOn: []string{
				"react-is@16.8.6",
			},
		},
		{
			ID: "home-or-tmp@2.0.0",
			DependsOn: []string{
				"os-homedir@1.0.2",
				"os-tmpdir@1.0.2",
			},
		},
		{
			ID: "homedir-polyfill@1.0.3",
			DependsOn: []string{
				"parse-passwd@1.0.0",
			},
		},
		{
			ID: "hpack.js@2.1.6",
			DependsOn: []string{
				"inherits@2.0.3",
				"obuf@1.1.2",
				"readable-stream@2.3.6",
				"wbuf@1.7.3",
			},
		},
		{
			ID: "html-element-map@1.0.1",
			DependsOn: []string{
				"array-filter@1.0.0",
			},
		},
		{
			ID: "html-encoding-sniffer@1.0.2",
			DependsOn: []string{
				"whatwg-encoding@1.0.5",
			},
		},
		{
			ID: "html-minifier@3.5.21",
			DependsOn: []string{
				"camel-case@3.0.0",
				"clean-css@4.2.1",
				"commander@2.17.1",
				"he@1.2.0",
				"param-case@2.1.1",
				"relateurl@0.2.7",
				"uglify-js@3.4.10",
			},
		},
		{
			ID: "html-webpack-harddisk-plugin@1.0.1",
			DependsOn: []string{
				"mkdirp@0.5.1",
			},
		},
		{
			ID: "html-webpack-plugin@3.2.0",
			DependsOn: []string{
				"html-minifier@3.5.21",
				"loader-utils@0.2.17",
				"lodash@4.17.11",
				"pretty-error@2.1.1",
				"tapable@1.1.3",
				"toposort@1.0.7",
				"util.promisify@1.0.0",
			},
		},
		{
			ID: "html-webpack-plugin@4.0.0-beta.5",
			DependsOn: []string{
				"html-minifier@3.5.21",
				"loader-utils@1.2.3",
				"lodash@4.17.11",
				"pretty-error@2.1.1",
				"tapable@1.1.3",
				"util.promisify@1.0.0",
			},
		},
		{
			ID: "htmlparser2@3.10.1",
			DependsOn: []string{
				"domelementtype@1.3.1",
				"domhandler@2.4.2",
				"domutils@1.7.0",
				"entities@1.1.2",
				"inherits@2.0.3",
				"readable-stream@3.3.0",
			},
		},
		{
			ID: "http-errors@1.6.3",
			DependsOn: []string{
				"depd@1.1.2",
				"inherits@2.0.3",
				"setprototypeof@1.1.0",
				"statuses@1.5.0",
			},
		},
		{
			ID: "http-proxy-agent@2.1.0",
			DependsOn: []string{
				"agent-base@4.2.1",
				"debug@3.1.0",
			},
		},
		{
			ID: "http-proxy-middleware@0.19.1",
			DependsOn: []string{
				"http-proxy@1.17.0",
				"is-glob@4.0.1",
				"lodash@4.17.11",
				"micromatch@3.1.10",
			},
		},
		{
			ID: "http-proxy@1.17.0",
			DependsOn: []string{
				"eventemitter3@3.1.2",
				"follow-redirects@1.7.0",
				"requires-port@1.0.0",
			},
		},
		{
			ID: "http-signature@1.2.0",
			DependsOn: []string{
				"assert-plus@1.0.0",
				"jsprim@1.4.1",
				"sshpk@1.16.1",
			},
		},
		{
			ID: "https-proxy-agent@2.2.1",
			DependsOn: []string{
				"agent-base@4.2.1",
				"debug@3.2.6",
			},
		},
		{
			ID: "humanize-ms@1.2.1",
			DependsOn: []string{
				"ms@2.1.1",
			},
		},
		{
			ID: "husky@1.3.1",
			DependsOn: []string{
				"cosmiconfig@5.2.1",
				"execa@1.0.0",
				"find-up@3.0.0",
				"get-stdin@6.0.0",
				"is-ci@2.0.0",
				"pkg-dir@3.0.0",
				"please-upgrade-node@3.1.1",
				"read-pkg@4.0.1",
				"run-node@1.0.0",
				"slash@2.0.0",
			},
		},
		{
			ID: "iconv-lite@0.4.23",
			DependsOn: []string{
				"safer-buffer@2.1.2",
			},
		},
		{
			ID: "iconv-lite@0.4.24",
			DependsOn: []string{
				"safer-buffer@2.1.2",
			},
		},
		{
			ID: "icss-utils@2.1.0",
			DependsOn: []string{
				"postcss@6.0.23",
			},
		},
		{
			ID: "ignore-walk@3.0.1",
			DependsOn: []string{
				"minimatch@3.0.4",
			},
		},
		{
			ID: "import-cwd@2.1.0",
			DependsOn: []string{
				"import-from@2.1.0",
			},
		},
		{
			ID: "import-fresh@2.0.0",
			DependsOn: []string{
				"caller-path@2.0.0",
				"resolve-from@3.0.0",
			},
		},
		{
			ID: "import-fresh@3.0.0",
			DependsOn: []string{
				"parent-module@1.0.1",
				"resolve-from@4.0.0",
			},
		},
		{
			ID: "import-from@2.1.0",
			DependsOn: []string{
				"resolve-from@3.0.0",
			},
		},
		{
			ID: "import-local@1.0.0",
			DependsOn: []string{
				"pkg-dir@2.0.0",
				"resolve-cwd@2.0.0",
			},
		},
		{
			ID: "import-local@2.0.0",
			DependsOn: []string{
				"pkg-dir@3.0.0",
				"resolve-cwd@2.0.0",
			},
		},
		{
			ID: "indefinite-observable@1.0.2",
			DependsOn: []string{
				"symbol-observable@1.2.0",
			},
		},
		{
			ID: "inflight@1.0.6",
			DependsOn: []string{
				"once@1.4.0",
				"wrappy@1.0.2",
			},
		},
		{
			ID: "init-package-json@1.10.3",
			DependsOn: []string{
				"glob@7.1.4",
				"npm-package-arg@6.1.0",
				"promzard@0.3.0",
				"read@1.0.7",
				"read-package-json@2.0.13",
				"semver@5.7.0",
				"validate-npm-package-license@3.0.4",
				"validate-npm-package-name@3.0.0",
			},
		},
		{
			ID: "inquirer@6.2.0",
			DependsOn: []string{
				"ansi-escapes@3.2.0",
				"chalk@2.4.2",
				"cli-cursor@2.1.0",
				"cli-width@2.2.0",
				"external-editor@3.0.3",
				"figures@2.0.0",
				"lodash@4.17.11",
				"mute-stream@0.0.7",
				"run-async@2.3.0",
				"rxjs@6.5.2",
				"string-width@2.1.1",
				"strip-ansi@4.0.0",
				"through@2.3.8",
			},
		},
		{
			ID: "inquirer@0.11.4",
			DependsOn: []string{
				"ansi-escapes@1.4.0",
				"ansi-regex@2.1.1",
				"chalk@1.1.3",
				"cli-cursor@1.0.2",
				"cli-width@1.1.1",
				"figures@1.7.0",
				"lodash@3.10.1",
				"readline2@1.0.1",
				"run-async@0.1.0",
				"rx-lite@3.1.2",
				"string-width@1.0.2",
				"strip-ansi@3.0.1",
				"through@2.3.8",
			},
		},
		{
			ID: "inquirer@6.3.1",
			DependsOn: []string{
				"ansi-escapes@3.2.0",
				"chalk@2.4.2",
				"cli-cursor@2.1.0",
				"cli-width@2.2.0",
				"external-editor@3.0.3",
				"figures@2.0.0",
				"lodash@4.17.11",
				"mute-stream@0.0.7",
				"run-async@2.3.0",
				"rxjs@6.5.2",
				"string-width@2.1.1",
				"strip-ansi@5.2.0",
				"through@2.3.8",
			},
		},
		{
			ID: "internal-ip@4.3.0",
			DependsOn: []string{
				"default-gateway@4.2.0",
				"ipaddr.js@1.9.0",
			},
		},
		{
			ID: "intl-messageformat@2.2.0",
			DependsOn: []string{
				"intl-messageformat-parser@1.4.0",
			},
		},
		{
			ID: "invariant@2.2.4",
			DependsOn: []string{
				"loose-envify@1.4.0",
			},
		},
		{
			ID: "is-accessor-descriptor@0.1.6",
			DependsOn: []string{
				"kind-of@3.2.2",
			},
		},
		{
			ID: "is-accessor-descriptor@1.0.0",
			DependsOn: []string{
				"kind-of@6.0.2",
			},
		},
		{
			ID: "is-binary-path@1.0.1",
			DependsOn: []string{
				"binary-extensions@1.13.1",
			},
		},
		{
			ID: "is-ci@1.2.1",
			DependsOn: []string{
				"ci-info@1.6.0",
			},
		},
		{
			ID: "is-ci@2.0.0",
			DependsOn: []string{
				"ci-info@2.0.0",
			},
		},
		{
			ID: "is-cidr@3.0.0",
			DependsOn: []string{
				"cidr-regex@2.0.10",
			},
		},
		{
			ID: "is-data-descriptor@0.1.4",
			DependsOn: []string{
				"kind-of@3.2.2",
			},
		},
		{
			ID: "is-data-descriptor@1.0.0",
			DependsOn: []string{
				"kind-of@6.0.2",
			},
		},
		{
			ID: "is-descriptor@0.1.6",
			DependsOn: []string{
				"is-accessor-descriptor@0.1.6",
				"is-data-descriptor@0.1.4",
				"kind-of@5.1.0",
			},
		},
		{
			ID: "is-descriptor@1.0.2",
			DependsOn: []string{
				"is-accessor-descriptor@1.0.0",
				"is-data-descriptor@1.0.0",
				"kind-of@6.0.2",
			},
		},
		{
			ID: "is-equal-shallow@0.1.3",
			DependsOn: []string{
				"is-primitive@2.0.0",
			},
		},
		{
			ID: "is-extendable@1.0.1",
			DependsOn: []string{
				"is-plain-object@2.0.4",
			},
		},
		{
			ID: "is-finite@1.0.2",
			DependsOn: []string{
				"number-is-nan@1.0.1",
			},
		},
		{
			ID: "is-fullwidth-code-point@1.0.0",
			DependsOn: []string{
				"number-is-nan@1.0.1",
			},
		},
		{
			ID: "is-glob@2.0.1",
			DependsOn: []string{
				"is-extglob@1.0.0",
			},
		},
		{
			ID: "is-glob@3.1.0",
			DependsOn: []string{
				"is-extglob@2.1.1",
			},
		},
		{
			ID: "is-glob@4.0.1",
			DependsOn: []string{
				"is-extglob@2.1.1",
			},
		},
		{
			ID: "is-installed-globally@0.1.0",
			DependsOn: []string{
				"global-dirs@0.1.1",
				"is-path-inside@1.0.1",
			},
		},
		{
			ID: "is-number@2.1.0",
			DependsOn: []string{
				"kind-of@3.2.2",
			},
		},
		{
			ID: "is-number@3.0.0",
			DependsOn: []string{
				"kind-of@3.2.2",
			},
		},
		{
			ID: "is-observable@1.1.0",
			DependsOn: []string{
				"symbol-observable@1.2.0",
			},
		},
		{
			ID: "is-path-in-cwd@1.0.1",
			DependsOn: []string{
				"is-path-inside@1.0.1",
			},
		},
		{
			ID: "is-path-in-cwd@2.1.0",
			DependsOn: []string{
				"is-path-inside@2.1.0",
			},
		},
		{
			ID: "is-path-inside@1.0.1",
			DependsOn: []string{
				"path-is-inside@1.0.2",
			},
		},
		{
			ID: "is-path-inside@2.1.0",
			DependsOn: []string{
				"path-is-inside@1.0.2",
			},
		},
		{
			ID: "is-plain-object@2.0.4",
			DependsOn: []string{
				"isobject@3.0.1",
			},
		},
		{
			ID: "is-regex@1.0.4",
			DependsOn: []string{
				"has@1.0.3",
			},
		},
		{
			ID: "is-symbol@1.0.2",
			DependsOn: []string{
				"has-symbols@1.0.0",
			},
		},
		{
			ID: "isobject@2.1.0",
			DependsOn: []string{
				"isarray@1.0.0",
			},
		},
		{
			ID: "isomorphic-fetch@2.2.1",
			DependsOn: []string{
				"node-fetch@1.7.3",
				"whatwg-fetch@3.0.0",
			},
		},
		{
			ID: "istanbul-api@1.3.7",
			DependsOn: []string{
				"async@2.6.2",
				"fileset@2.0.3",
				"istanbul-lib-coverage@1.2.1",
				"istanbul-lib-hook@1.2.2",
				"istanbul-lib-instrument@1.10.2",
				"istanbul-lib-report@1.1.5",
				"istanbul-lib-source-maps@1.2.6",
				"istanbul-reports@1.5.1",
				"js-yaml@3.13.1",
				"mkdirp@0.5.1",
				"once@1.4.0",
			},
		},
		{
			ID: "istanbul-lib-hook@1.2.2",
			DependsOn: []string{
				"append-transform@0.4.0",
			},
		},
		{
			ID: "istanbul-lib-instrument@1.10.2",
			DependsOn: []string{
				"babel-generator@6.26.1",
				"babel-template@6.26.0",
				"babel-traverse@6.26.0",
				"babel-types@6.26.0",
				"babylon@6.18.0",
				"istanbul-lib-coverage@1.2.1",
				"semver@5.7.0",
			},
		},
		{
			ID: "istanbul-lib-report@1.1.5",
			DependsOn: []string{
				"istanbul-lib-coverage@1.2.1",
				"mkdirp@0.5.1",
				"path-parse@1.0.6",
				"supports-color@3.2.3",
			},
		},
		{
			ID: "istanbul-lib-source-maps@1.2.6",
			DependsOn: []string{
				"debug@3.2.6",
				"istanbul-lib-coverage@1.2.1",
				"mkdirp@0.5.1",
				"rimraf@2.6.3",
				"source-map@0.5.7",
			},
		},
		{
			ID: "istanbul-reports@1.5.1",
			DependsOn: []string{
				"handlebars@4.1.2",
			},
		},
		{
			ID: "isurl@1.0.0",
			DependsOn: []string{
				"has-to-string-tag-x@1.4.1",
				"is-object@1.0.1",
			},
		},
		{
			ID: "jest-changed-files@23.4.2",
			DependsOn: []string{
				"throat@4.1.0",
			},
		},
		{
			ID: "jest-cli@23.6.0",
			DependsOn: []string{
				"ansi-escapes@3.2.0",
				"chalk@2.4.2",
				"exit@0.1.2",
				"glob@7.1.4",
				"graceful-fs@4.1.15",
				"import-local@1.0.0",
				"is-ci@1.2.1",
				"istanbul-api@1.3.7",
				"istanbul-lib-coverage@1.2.1",
				"istanbul-lib-instrument@1.10.2",
				"istanbul-lib-source-maps@1.2.6",
				"jest-changed-files@23.4.2",
				"jest-config@23.6.0",
				"jest-environment-jsdom@23.4.0",
				"jest-get-type@22.4.3",
				"jest-haste-map@23.6.0",
				"jest-message-util@23.4.0",
				"jest-regex-util@23.3.0",
				"jest-resolve-dependencies@23.6.0",
				"jest-runner@23.6.0",
				"jest-runtime@23.6.0",
				"jest-snapshot@23.6.0",
				"jest-util@23.4.0",
				"jest-validate@23.6.0",
				"jest-watcher@23.4.0",
				"jest-worker@23.2.0",
				"micromatch@2.3.11",
				"node-notifier@5.4.0",
				"prompts@0.1.14",
				"realpath-native@1.1.0",
				"rimraf@2.6.3",
				"slash@1.0.0",
				"string-length@2.0.0",
				"strip-ansi@4.0.0",
				"which@1.3.1",
				"yargs@11.1.0",
			},
		},
		{
			ID: "jest-config@23.6.0",
			DependsOn: []string{
				"babel-core@6.26.3",
				"babel-jest@23.6.0",
				"chalk@2.4.2",
				"glob@7.1.4",
				"jest-environment-jsdom@23.4.0",
				"jest-environment-node@23.4.0",
				"jest-get-type@22.4.3",
				"jest-jasmine2@23.6.0",
				"jest-regex-util@23.3.0",
				"jest-resolve@23.6.0",
				"jest-util@23.4.0",
				"jest-validate@23.6.0",
				"micromatch@2.3.11",
				"pretty-format@23.6.0",
			},
		},
		{
			ID: "jest-diff@23.6.0",
			DependsOn: []string{
				"chalk@2.4.2",
				"diff@3.5.0",
				"jest-get-type@22.4.3",
				"pretty-format@23.6.0",
			},
		},
		{
			ID: "jest-docblock@23.2.0",
			DependsOn: []string{
				"detect-newline@2.1.0",
			},
		},
		{
			ID: "jest-each@23.6.0",
			DependsOn: []string{
				"chalk@2.4.2",
				"pretty-format@23.6.0",
			},
		},
		{
			ID: "jest-environment-jsdom@23.4.0",
			DependsOn: []string{
				"jest-mock@23.2.0",
				"jest-util@23.4.0",
				"jsdom@11.12.0",
			},
		},
		{
			ID: "jest-environment-node@23.4.0",
			DependsOn: []string{
				"jest-mock@23.2.0",
				"jest-util@23.4.0",
			},
		},
		{
			ID: "jest-haste-map@23.6.0",
			DependsOn: []string{
				"fb-watchman@2.0.0",
				"graceful-fs@4.1.15",
				"invariant@2.2.4",
				"jest-docblock@23.2.0",
				"jest-serializer@23.0.1",
				"jest-worker@23.2.0",
				"micromatch@2.3.11",
				"sane@2.5.2",
			},
		},
		{
			ID: "jest-jasmine2@23.6.0",
			DependsOn: []string{
				"babel-traverse@6.26.0",
				"chalk@2.4.2",
				"co@4.6.0",
				"expect@23.6.0",
				"is-generator-fn@1.0.0",
				"jest-diff@23.6.0",
				"jest-each@23.6.0",
				"jest-matcher-utils@23.6.0",
				"jest-message-util@23.4.0",
				"jest-snapshot@23.6.0",
				"jest-util@23.4.0",
				"pretty-format@23.6.0",
			},
		},
		{
			ID: "jest-leak-detector@23.6.0",
			DependsOn: []string{
				"pretty-format@23.6.0",
			},
		},
		{
			ID: "jest-matcher-utils@23.6.0",
			DependsOn: []string{
				"chalk@2.4.2",
				"jest-get-type@22.4.3",
				"pretty-format@23.6.0",
			},
		},
		{
			ID: "jest-message-util@23.4.0",
			DependsOn: []string{
				"@babel/code-frame@7.0.0",
				"chalk@2.4.2",
				"micromatch@2.3.11",
				"slash@1.0.0",
				"stack-utils@1.0.2",
			},
		},
		{
			ID: "jest-resolve-dependencies@23.6.0",
			DependsOn: []string{
				"jest-regex-util@23.3.0",
				"jest-snapshot@23.6.0",
			},
		},
		{
			ID: "jest-resolve@23.6.0",
			DependsOn: []string{
				"browser-resolve@1.11.3",
				"chalk@2.4.2",
				"realpath-native@1.1.0",
			},
		},
		{
			ID: "jest-runner@23.6.0",
			DependsOn: []string{
				"exit@0.1.2",
				"graceful-fs@4.1.15",
				"jest-config@23.6.0",
				"jest-docblock@23.2.0",
				"jest-haste-map@23.6.0",
				"jest-jasmine2@23.6.0",
				"jest-leak-detector@23.6.0",
				"jest-message-util@23.4.0",
				"jest-runtime@23.6.0",
				"jest-util@23.4.0",
				"jest-worker@23.2.0",
				"source-map-support@0.5.12",
				"throat@4.1.0",
			},
		},
		{
			ID: "jest-runtime@23.6.0",
			DependsOn: []string{
				"babel-core@6.26.3",
				"babel-plugin-istanbul@4.1.6",
				"chalk@2.4.2",
				"convert-source-map@1.6.0",
				"exit@0.1.2",
				"fast-json-stable-stringify@2.0.0",
				"graceful-fs@4.1.15",
				"jest-config@23.6.0",
				"jest-haste-map@23.6.0",
				"jest-message-util@23.4.0",
				"jest-regex-util@23.3.0",
				"jest-resolve@23.6.0",
				"jest-snapshot@23.6.0",
				"jest-util@23.4.0",
				"jest-validate@23.6.0",
				"micromatch@2.3.11",
				"realpath-native@1.1.0",
				"slash@1.0.0",
				"strip-bom@3.0.0",
				"write-file-atomic@2.4.2",
				"yargs@11.1.0",
			},
		},
		{
			ID: "jest-snapshot@23.6.0",
			DependsOn: []string{
				"babel-types@6.26.0",
				"chalk@2.4.2",
				"jest-diff@23.6.0",
				"jest-matcher-utils@23.6.0",
				"jest-message-util@23.4.0",
				"jest-resolve@23.6.0",
				"mkdirp@0.5.1",
				"natural-compare@1.4.0",
				"pretty-format@23.6.0",
				"semver@5.7.0",
			},
		},
		{
			ID: "jest-util@23.4.0",
			DependsOn: []string{
				"callsites@2.0.0",
				"chalk@2.4.2",
				"graceful-fs@4.1.15",
				"is-ci@1.2.1",
				"jest-message-util@23.4.0",
				"mkdirp@0.5.1",
				"slash@1.0.0",
				"source-map@0.6.1",
			},
		},
		{
			ID: "jest-validate@23.6.0",
			DependsOn: []string{
				"chalk@2.4.2",
				"jest-get-type@22.4.3",
				"leven@2.1.0",
				"pretty-format@23.6.0",
			},
		},
		{
			ID: "jest-watcher@23.4.0",
			DependsOn: []string{
				"ansi-escapes@3.2.0",
				"chalk@2.4.2",
				"string-length@2.0.0",
			},
		},
		{
			ID: "jest-worker@23.2.0",
			DependsOn: []string{
				"merge-stream@1.0.1",
			},
		},
		{
			ID: "jest@23.6.0",
			DependsOn: []string{
				"import-local@1.0.0",
				"jest-cli@23.6.0",
			},
		},
		{
			ID: "js-yaml@3.13.1",
			DependsOn: []string{
				"argparse@1.0.10",
				"esprima@4.0.1",
			},
		},
		{
			ID: "jscodeshift@0.5.1",
			DependsOn: []string{
				"babel-plugin-transform-flow-strip-types@6.22.0",
				"babel-preset-es2015@6.24.1",
				"babel-preset-stage-1@6.24.1",
				"babel-register@6.26.0",
				"babylon@7.0.0-beta.47",
				"colors@1.3.3",
				"flow-parser@0.98.1",
				"lodash@4.17.11",
				"micromatch@2.3.11",
				"neo-async@2.6.1",
				"node-dir@0.1.8",
				"nomnom@1.8.1",
				"recast@0.15.5",
				"temp@0.8.3",
				"write-file-atomic@1.3.4",
			},
		},
		{
			ID: "jsdom@11.12.0",
			DependsOn: []string{
				"abab@2.0.0",
				"acorn@5.7.3",
				"acorn-globals@4.3.2",
				"array-equal@1.0.0",
				"cssom@0.3.6",
				"cssstyle@1.2.2",
				"data-urls@1.1.0",
				"domexception@1.0.1",
				"escodegen@1.11.1",
				"html-encoding-sniffer@1.0.2",
				"left-pad@1.3.0",
				"nwsapi@2.1.4",
				"parse5@4.0.0",
				"pn@1.1.0",
				"request@2.88.0",
				"request-promise-native@1.0.7",
				"sax@1.2.4",
				"symbol-tree@3.2.2",
				"tough-cookie@2.5.0",
				"w3c-hr-time@1.0.1",
				"webidl-conversions@4.0.2",
				"whatwg-encoding@1.0.5",
				"whatwg-mimetype@2.3.0",
				"whatwg-url@6.5.0",
				"ws@5.2.2",
				"xml-name-validator@3.0.0",
			},
		},
		{
			ID: "json5@1.0.1",
			DependsOn: []string{
				"minimist@1.2.0",
			},
		},
		{
			ID: "json5@2.1.0",
			DependsOn: []string{
				"minimist@1.2.0",
			},
		},
		{
			ID: "jsprim@1.4.1",
			DependsOn: []string{
				"assert-plus@1.0.0",
				"extsprintf@1.3.0",
				"json-schema@0.2.3",
				"verror@1.10.0",
			},
		},
		{
			ID: "jss-camel-case@6.1.0",
			DependsOn: []string{
				"hyphenate-style-name@1.0.3",
			},
		},
		{
			ID: "jss-nested@6.0.1",
			DependsOn: []string{
				"warning@3.0.0",
			},
		},
		{
			ID: "jss-vendor-prefixer@7.0.0",
			DependsOn: []string{
				"css-vendor@0.3.8",
			},
		},
		{
			ID: "jss@9.8.7",
			DependsOn: []string{
				"is-in-browser@1.1.3",
				"symbol-observable@1.2.0",
				"warning@3.0.0",
			},
		},
		{
			ID: "jsx-ast-utils@2.1.0",
			DependsOn: []string{
				"array-includes@3.0.3",
			},
		},
		{
			ID: "kind-of@2.0.1",
			DependsOn: []string{
				"is-buffer@1.1.6",
			},
		},
		{
			ID: "kind-of@3.2.2",
			DependsOn: []string{
				"is-buffer@1.1.6",
			},
		},
		{
			ID: "kind-of@4.0.0",
			DependsOn: []string{
				"is-buffer@1.1.6",
			},
		},
		{
			ID: "latest-version@3.1.0",
			DependsOn: []string{
				"package-json@4.0.1",
			},
		},
		{
			ID: "lazy-universal-dotenv@2.0.0",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"app-root-dir@1.0.2",
				"core-js@2.6.5",
				"dotenv@6.2.0",
				"dotenv-expand@4.2.0",
			},
		},
		{
			ID: "lcid@1.0.0",
			DependsOn: []string{
				"invert-kv@1.0.0",
			},
		},
		{
			ID: "lcid@2.0.0",
			DependsOn: []string{
				"invert-kv@2.0.0",
			},
		},
		{
			ID: "levn@0.3.0",
			DependsOn: []string{
				"prelude-ls@1.1.2",
				"type-check@0.3.2",
			},
		},
		{
			ID: "libcipm@3.0.3",
			DependsOn: []string{
				"bin-links@1.1.2",
				"bluebird@3.5.4",
				"figgy-pudding@3.5.1",
				"find-npm-prefix@1.0.2",
				"graceful-fs@4.1.15",
				"ini@1.3.5",
				"lock-verify@2.1.0",
				"mkdirp@0.5.1",
				"npm-lifecycle@2.1.1",
				"npm-logical-tree@1.2.1",
				"npm-package-arg@6.1.0",
				"pacote@9.5.0",
				"read-package-json@2.0.13",
				"rimraf@2.6.3",
				"worker-farm@1.7.0",
			},
		},
		{
			ID: "libnpm@2.0.1",
			DependsOn: []string{
				"bin-links@1.1.2",
				"bluebird@3.5.4",
				"find-npm-prefix@1.0.2",
				"libnpmaccess@3.0.1",
				"libnpmconfig@1.2.1",
				"libnpmhook@5.0.2",
				"libnpmorg@1.0.0",
				"libnpmpublish@1.1.1",
				"libnpmsearch@2.0.0",
				"libnpmteam@1.0.1",
				"lock-verify@2.1.0",
				"npm-lifecycle@2.1.1",
				"npm-logical-tree@1.2.1",
				"npm-package-arg@6.1.0",
				"npm-profile@4.0.1",
				"npm-registry-fetch@3.9.0",
				"npmlog@4.1.2",
				"pacote@9.5.0",
				"read-package-json@2.0.13",
				"stringify-package@1.0.0",
			},
		},
		{
			ID: "libnpmaccess@3.0.1",
			DependsOn: []string{
				"aproba@2.0.0",
				"get-stream@4.1.0",
				"npm-package-arg@6.1.0",
				"npm-registry-fetch@3.9.0",
			},
		},
		{
			ID: "libnpmconfig@1.2.1",
			DependsOn: []string{
				"figgy-pudding@3.5.1",
				"find-up@3.0.0",
				"ini@1.3.5",
			},
		},
		{
			ID: "libnpmhook@5.0.2",
			DependsOn: []string{
				"aproba@2.0.0",
				"figgy-pudding@3.5.1",
				"get-stream@4.1.0",
				"npm-registry-fetch@3.9.0",
			},
		},
		{
			ID: "libnpmorg@1.0.0",
			DependsOn: []string{
				"aproba@2.0.0",
				"figgy-pudding@3.5.1",
				"get-stream@4.1.0",
				"npm-registry-fetch@3.9.0",
			},
		},
		{
			ID: "libnpmpublish@1.1.1",
			DependsOn: []string{
				"aproba@2.0.0",
				"figgy-pudding@3.5.1",
				"get-stream@4.1.0",
				"lodash.clonedeep@4.5.0",
				"normalize-package-data@2.5.0",
				"npm-package-arg@6.1.0",
				"npm-registry-fetch@3.9.0",
				"semver@5.7.0",
				"ssri@6.0.1",
			},
		},
		{
			ID: "libnpmsearch@2.0.0",
			DependsOn: []string{
				"figgy-pudding@3.5.1",
				"get-stream@4.1.0",
				"npm-registry-fetch@3.9.0",
			},
		},
		{
			ID: "libnpmteam@1.0.1",
			DependsOn: []string{
				"aproba@2.0.0",
				"figgy-pudding@3.5.1",
				"get-stream@4.1.0",
				"npm-registry-fetch@3.9.0",
			},
		},
		{
			ID: "libnpx@10.2.0",
			DependsOn: []string{
				"dotenv@5.0.1",
				"npm-package-arg@6.1.0",
				"rimraf@2.6.3",
				"safe-buffer@5.1.2",
				"update-notifier@2.5.0",
				"which@1.3.1",
				"y18n@4.0.0",
				"yargs@11.1.0",
			},
		},
		{
			ID: "lint-staged@7.3.0",
			DependsOn: []string{
				"chalk@2.4.2",
				"commander@2.20.0",
				"cosmiconfig@5.2.1",
				"debug@3.2.6",
				"dedent@0.7.0",
				"execa@0.9.0",
				"find-parent-dir@0.3.0",
				"is-glob@4.0.1",
				"is-windows@1.0.2",
				"jest-validate@23.6.0",
				"listr@0.14.3",
				"lodash@4.17.11",
				"log-symbols@2.2.0",
				"micromatch@3.1.10",
				"npm-which@3.0.1",
				"p-map@1.2.0",
				"path-is-inside@1.0.2",
				"pify@3.0.0",
				"please-upgrade-node@3.1.1",
				"staged-git-files@1.1.1",
				"string-argv@0.0.2",
				"stringify-object@3.3.0",
			},
		},
		{
			ID: "listr-update-renderer@0.5.0",
			DependsOn: []string{
				"chalk@1.1.3",
				"cli-truncate@0.2.1",
				"elegant-spinner@1.0.1",
				"figures@1.7.0",
				"indent-string@3.2.0",
				"log-symbols@1.0.2",
				"log-update@2.3.0",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID: "listr-verbose-renderer@0.5.0",
			DependsOn: []string{
				"chalk@2.4.2",
				"cli-cursor@2.1.0",
				"date-fns@1.30.1",
				"figures@2.0.0",
			},
		},
		{
			ID: "listr@0.14.3",
			DependsOn: []string{
				"@samverschueren/stream-to-observable@0.3.0",
				"is-observable@1.1.0",
				"is-promise@2.1.0",
				"is-stream@1.1.0",
				"listr-silent-renderer@1.1.1",
				"listr-update-renderer@0.5.0",
				"listr-verbose-renderer@0.5.0",
				"p-map@2.1.0",
				"rxjs@6.5.2",
			},
		},
		{
			ID: "load-json-file@1.1.0",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"parse-json@2.2.0",
				"pify@2.3.0",
				"pinkie-promise@2.0.1",
				"strip-bom@2.0.0",
			},
		},
		{
			ID: "load-json-file@2.0.0",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"parse-json@2.2.0",
				"pify@2.3.0",
				"strip-bom@3.0.0",
			},
		},
		{
			ID: "load-json-file@4.0.0",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"parse-json@4.0.0",
				"pify@3.0.0",
				"strip-bom@3.0.0",
			},
		},
		{
			ID: "loader-fs-cache@1.0.2",
			DependsOn: []string{
				"find-cache-dir@0.1.1",
				"mkdirp@0.5.1",
			},
		},
		{
			ID: "loader-utils@1.1.0",
			DependsOn: []string{
				"big.js@3.2.0",
				"emojis-list@2.1.0",
				"json5@0.5.1",
			},
		},
		{
			ID: "loader-utils@0.2.17",
			DependsOn: []string{
				"big.js@3.2.0",
				"emojis-list@2.1.0",
				"json5@0.5.1",
				"object-assign@4.1.1",
			},
		},
		{
			ID: "loader-utils@1.2.3",
			DependsOn: []string{
				"big.js@5.2.2",
				"emojis-list@2.1.0",
				"json5@1.0.1",
			},
		},
		{
			ID: "locate-path@2.0.0",
			DependsOn: []string{
				"p-locate@2.0.0",
				"path-exists@3.0.0",
			},
		},
		{
			ID: "locate-path@3.0.0",
			DependsOn: []string{
				"p-locate@3.0.0",
				"path-exists@3.0.0",
			},
		},
		{
			ID: "lock-verify@2.1.0",
			DependsOn: []string{
				"npm-package-arg@6.1.0",
				"semver@5.7.0",
			},
		},
		{
			ID: "lockfile@1.0.4",
			DependsOn: []string{
				"signal-exit@3.0.2",
			},
		},
		{
			ID: "lodash._baseuniq@4.6.0",
			DependsOn: []string{
				"lodash._createset@4.0.3",
				"lodash._root@3.0.1",
			},
		},
		{
			ID: "log-symbols@1.0.2",
			DependsOn: []string{
				"chalk@1.1.3",
			},
		},
		{
			ID: "log-symbols@2.2.0",
			DependsOn: []string{
				"chalk@2.4.2",
			},
		},
		{
			ID: "log-update@2.3.0",
			DependsOn: []string{
				"ansi-escapes@3.2.0",
				"cli-cursor@2.1.0",
				"wrap-ansi@3.0.1",
			},
		},
		{
			ID: "loose-envify@1.4.0",
			DependsOn: []string{
				"js-tokens@4.0.0",
			},
		},
		{
			ID: "lru-cache@4.1.5",
			DependsOn: []string{
				"pseudomap@1.0.2",
				"yallist@2.1.2",
			},
		},
		{
			ID: "lru-cache@5.1.1",
			DependsOn: []string{
				"yallist@3.0.3",
			},
		},
		{
			ID: "make-dir@1.3.0",
			DependsOn: []string{
				"pify@3.0.0",
			},
		},
		{
			ID: "make-dir@2.1.0",
			DependsOn: []string{
				"pify@4.0.1",
				"semver@5.7.0",
			},
		},
		{
			ID: "make-fetch-happen@4.0.1",
			DependsOn: []string{
				"agentkeepalive@3.5.2",
				"cacache@11.3.2",
				"http-cache-semantics@3.8.1",
				"http-proxy-agent@2.1.0",
				"https-proxy-agent@2.2.1",
				"lru-cache@4.1.5",
				"mississippi@3.0.0",
				"node-fetch-npm@2.0.2",
				"promise-retry@1.1.1",
				"socks-proxy-agent@4.0.2",
				"ssri@6.0.1",
			},
		},
		{
			ID: "makeerror@1.0.11",
			DependsOn: []string{
				"tmpl@1.0.4",
			},
		},
		{
			ID: "map-age-cleaner@0.1.3",
			DependsOn: []string{
				"p-defer@1.0.0",
			},
		},
		{
			ID: "map-visit@1.0.0",
			DependsOn: []string{
				"object-visit@1.0.1",
			},
		},
		{
			ID: "marksy@6.1.0",
			DependsOn: []string{
				"babel-standalone@6.26.0",
				"he@1.2.0",
				"marked@0.3.19",
			},
		},
		{
			ID: "md5.js@1.3.5",
			DependsOn: []string{
				"hash-base@3.0.4",
				"inherits@2.0.3",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "md5@2.2.1",
			DependsOn: []string{
				"charenc@0.0.2",
				"crypt@0.0.2",
				"is-buffer@1.1.6",
			},
		},
		{
			ID: "mem@1.1.0",
			DependsOn: []string{
				"mimic-fn@1.2.0",
			},
		},
		{
			ID: "mem@4.3.0",
			DependsOn: []string{
				"map-age-cleaner@0.1.3",
				"mimic-fn@2.1.0",
				"p-is-promise@2.1.0",
			},
		},
		{
			ID: "memory-fs@0.4.1",
			DependsOn: []string{
				"errno@0.1.7",
				"readable-stream@2.3.6",
			},
		},
		{
			ID: "merge-deep@3.0.2",
			DependsOn: []string{
				"arr-union@3.1.0",
				"clone-deep@0.2.4",
				"kind-of@3.2.2",
			},
		},
		{
			ID: "merge-dirs@0.2.1",
			DependsOn: []string{
				"inquirer@0.11.4",
				"minimist@1.2.0",
				"node-fs@0.1.7",
				"path@0.12.7",
			},
		},
		{
			ID: "merge-stream@1.0.1",
			DependsOn: []string{
				"readable-stream@2.3.6",
			},
		},
		{
			ID: "micromatch@2.3.11",
			DependsOn: []string{
				"arr-diff@2.0.0",
				"array-unique@0.2.1",
				"braces@1.8.5",
				"expand-brackets@0.1.5",
				"extglob@0.3.2",
				"filename-regex@2.0.1",
				"is-extglob@1.0.0",
				"is-glob@2.0.1",
				"kind-of@3.2.2",
				"normalize-path@2.1.1",
				"object.omit@2.0.1",
				"parse-glob@3.0.4",
				"regex-cache@0.4.4",
			},
		},
		{
			ID: "micromatch@3.1.10",
			DependsOn: []string{
				"arr-diff@4.0.0",
				"array-unique@0.3.2",
				"braces@2.3.2",
				"define-property@2.0.2",
				"extend-shallow@3.0.2",
				"extglob@2.0.4",
				"fragment-cache@0.2.1",
				"kind-of@6.0.2",
				"nanomatch@1.2.13",
				"object.pick@1.3.0",
				"regex-not@1.0.2",
				"snapdragon@0.8.2",
				"to-regex@3.0.2",
			},
		},
		{
			ID: "miller-rabin@4.0.1",
			DependsOn: []string{
				"bn.js@4.11.8",
				"brorand@1.1.0",
			},
		},
		{
			ID: "mime-types@2.1.24",
			DependsOn: []string{
				"mime-db@1.40.0",
			},
		},
		{
			ID: "min-document@2.19.0",
			DependsOn: []string{
				"dom-walk@0.1.1",
			},
		},
		{
			ID: "mini-css-extract-plugin@0.4.5",
			DependsOn: []string{
				"loader-utils@1.2.3",
				"schema-utils@1.0.0",
				"webpack-sources@1.3.0",
			},
		},
		{
			ID: "minimatch@3.0.4",
			DependsOn: []string{
				"brace-expansion@1.1.11",
			},
		},
		{
			ID: "minipass@2.3.5",
			DependsOn: []string{
				"safe-buffer@5.1.2",
				"yallist@3.0.3",
			},
		},
		{
			ID: "minizlib@1.2.1",
			DependsOn: []string{
				"minipass@2.3.5",
			},
		},
		{
			ID: "mississippi@2.0.0",
			DependsOn: []string{
				"concat-stream@1.6.2",
				"duplexify@3.7.1",
				"end-of-stream@1.4.1",
				"flush-write-stream@1.1.1",
				"from2@2.3.0",
				"parallel-transform@1.1.0",
				"pump@2.0.1",
				"pumpify@1.5.1",
				"stream-each@1.2.3",
				"through2@2.0.5",
			},
		},
		{
			ID: "mississippi@3.0.0",
			DependsOn: []string{
				"concat-stream@1.6.2",
				"duplexify@3.7.1",
				"end-of-stream@1.4.1",
				"flush-write-stream@1.1.1",
				"from2@2.3.0",
				"parallel-transform@1.1.0",
				"pump@3.0.0",
				"pumpify@1.5.1",
				"stream-each@1.2.3",
				"through2@2.0.5",
			},
		},
		{
			ID: "mixin-deep@1.3.1",
			DependsOn: []string{
				"for-in@1.0.2",
				"is-extendable@1.0.1",
			},
		},
		{
			ID: "mixin-object@2.0.1",
			DependsOn: []string{
				"for-in@0.1.8",
				"is-extendable@0.1.1",
			},
		},
		{
			ID: "mkdirp@0.5.1",
			DependsOn: []string{
				"minimist@0.0.8",
			},
		},
		{
			ID: "moment-timezone@0.5.23",
			DependsOn: []string{
				"moment@2.24.0",
			},
		},
		{
			ID: "move-concurrently@1.0.1",
			DependsOn: []string{
				"aproba@1.2.0",
				"copy-concurrently@1.0.5",
				"fs-write-stream-atomic@1.0.10",
				"mkdirp@0.5.1",
				"rimraf@2.6.3",
				"run-queue@1.0.3",
			},
		},
		{
			ID: "multicast-dns@6.2.3",
			DependsOn: []string{
				"dns-packet@1.3.1",
				"thunky@1.0.3",
			},
		},
		{
			ID: "nanomatch@1.2.13",
			DependsOn: []string{
				"arr-diff@4.0.0",
				"array-unique@0.3.2",
				"define-property@2.0.2",
				"extend-shallow@3.0.2",
				"fragment-cache@0.2.1",
				"is-windows@1.0.2",
				"kind-of@6.0.2",
				"object.pick@1.3.0",
				"regex-not@1.0.2",
				"snapdragon@0.8.2",
				"to-regex@3.0.2",
			},
		},
		{
			ID: "nearley@2.16.0",
			DependsOn: []string{
				"commander@2.20.0",
				"moo@0.4.3",
				"railroad-diagrams@1.0.0",
				"randexp@0.4.6",
				"semver@5.7.0",
			},
		},
		{
			ID: "needle@2.4.0",
			DependsOn: []string{
				"debug@3.2.6",
				"iconv-lite@0.4.24",
				"sax@1.2.4",
			},
		},
		{
			ID: "no-case@2.3.2",
			DependsOn: []string{
				"lower-case@1.1.4",
			},
		},
		{
			ID: "node-dir@0.1.17",
			DependsOn: []string{
				"minimatch@3.0.4",
			},
		},
		{
			ID: "node-fetch-npm@2.0.2",
			DependsOn: []string{
				"encoding@0.1.12",
				"json-parse-better-errors@1.0.2",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "node-fetch@1.7.3",
			DependsOn: []string{
				"encoding@0.1.12",
				"is-stream@1.1.0",
			},
		},
		{
			ID: "node-gyp@3.8.0",
			DependsOn: []string{
				"fstream@1.0.12",
				"glob@7.1.4",
				"graceful-fs@4.1.15",
				"mkdirp@0.5.1",
				"nopt@3.0.6",
				"npmlog@4.1.2",
				"osenv@0.1.5",
				"request@2.88.0",
				"rimraf@2.6.3",
				"semver@5.3.0",
				"tar@2.2.2",
				"which@1.3.1",
			},
		},
		{
			ID: "node-gyp@4.0.0",
			DependsOn: []string{
				"glob@7.1.4",
				"graceful-fs@4.1.15",
				"mkdirp@0.5.1",
				"nopt@3.0.6",
				"npmlog@4.1.2",
				"osenv@0.1.5",
				"request@2.88.0",
				"rimraf@2.6.3",
				"semver@5.3.0",
				"tar@4.4.8",
				"which@1.3.1",
			},
		},
		{
			ID: "node-libs-browser@2.2.0",
			DependsOn: []string{
				"assert@1.5.0",
				"browserify-zlib@0.2.0",
				"buffer@4.9.1",
				"console-browserify@1.1.0",
				"constants-browserify@1.0.0",
				"crypto-browserify@3.12.0",
				"domain-browser@1.2.0",
				"events@3.0.0",
				"https-browserify@1.0.0",
				"os-browserify@0.3.0",
				"path-browserify@0.0.0",
				"process@0.11.10",
				"punycode@1.4.1",
				"querystring-es3@0.2.1",
				"readable-stream@2.3.6",
				"stream-browserify@2.0.2",
				"stream-http@2.8.3",
				"string_decoder@1.2.0",
				"timers-browserify@2.0.10",
				"tty-browserify@0.0.0",
				"url@0.11.0",
				"util@0.11.1",
				"vm-browserify@0.0.4",
			},
		},
		{
			ID: "node-notifier@5.4.0",
			DependsOn: []string{
				"growly@1.3.0",
				"is-wsl@1.1.0",
				"semver@5.7.0",
				"shellwords@0.1.1",
				"which@1.3.1",
			},
		},
		{
			ID: "node-pre-gyp@0.12.0",
			DependsOn: []string{
				"detect-libc@1.0.3",
				"mkdirp@0.5.1",
				"needle@2.4.0",
				"nopt@4.0.1",
				"npm-packlist@1.4.1",
				"npmlog@4.1.2",
				"rc@1.2.8",
				"rimraf@2.6.3",
				"semver@5.7.0",
				"tar@4.4.8",
			},
		},
		{
			ID: "node-releases@1.1.19",
			DependsOn: []string{
				"semver@5.7.0",
			},
		},
		{
			ID: "nomnom@1.8.1",
			DependsOn: []string{
				"chalk@0.4.0",
				"underscore@1.6.0",
			},
		},
		{
			ID: "nopt@3.0.6",
			DependsOn: []string{
				"abbrev@1.1.1",
			},
		},
		{
			ID: "nopt@4.0.1",
			DependsOn: []string{
				"abbrev@1.1.1",
				"osenv@0.1.5",
			},
		},
		{
			ID: "normalize-package-data@2.5.0",
			DependsOn: []string{
				"hosted-git-info@2.7.1",
				"resolve@1.10.1",
				"semver@5.7.0",
				"validate-npm-package-license@3.0.4",
			},
		},
		{
			ID: "normalize-path@2.1.1",
			DependsOn: []string{
				"remove-trailing-separator@1.1.0",
			},
		},
		{
			ID: "npm-audit-report@1.3.2",
			DependsOn: []string{
				"cli-table3@0.5.1",
				"console-control-strings@1.1.0",
			},
		},
		{
			ID: "npm-install-checks@3.0.0",
			DependsOn: []string{
				"semver@5.7.0",
			},
		},
		{
			ID: "npm-lifecycle@2.1.1",
			DependsOn: []string{
				"byline@5.0.0",
				"graceful-fs@4.1.15",
				"node-gyp@4.0.0",
				"resolve-from@4.0.0",
				"slide@1.1.6",
				"uid-number@0.0.6",
				"umask@1.1.0",
				"which@1.3.1",
			},
		},
		{
			ID: "npm-package-arg@6.1.0",
			DependsOn: []string{
				"hosted-git-info@2.7.1",
				"osenv@0.1.5",
				"semver@5.7.0",
				"validate-npm-package-name@3.0.0",
			},
		},
		{
			ID: "npm-packlist@1.4.1",
			DependsOn: []string{
				"ignore-walk@3.0.1",
				"npm-bundled@1.0.6",
			},
		},
		{
			ID: "npm-path@2.0.4",
			DependsOn: []string{
				"which@1.3.1",
			},
		},
		{
			ID: "npm-pick-manifest@2.2.3",
			DependsOn: []string{
				"figgy-pudding@3.5.1",
				"npm-package-arg@6.1.0",
				"semver@5.7.0",
			},
		},
		{
			ID: "npm-profile@4.0.1",
			DependsOn: []string{
				"aproba@2.0.0",
				"figgy-pudding@3.5.1",
				"npm-registry-fetch@3.9.0",
			},
		},
		{
			ID: "npm-registry-fetch@3.9.0",
			DependsOn: []string{
				"JSONStream@1.3.5",
				"bluebird@3.5.4",
				"figgy-pudding@3.5.1",
				"lru-cache@4.1.5",
				"make-fetch-happen@4.0.1",
				"npm-package-arg@6.1.0",
			},
		},
		{
			ID: "npm-run-all@4.1.5",
			DependsOn: []string{
				"ansi-styles@3.2.1",
				"chalk@2.4.2",
				"cross-spawn@6.0.5",
				"memorystream@0.3.1",
				"minimatch@3.0.4",
				"pidtree@0.3.0",
				"read-pkg@3.0.0",
				"shell-quote@1.6.1",
				"string.prototype.padend@3.0.0",
			},
		},
		{
			ID: "npm-run-path@2.0.2",
			DependsOn: []string{
				"path-key@2.0.1",
			},
		},
		{
			ID: "npm-which@3.0.1",
			DependsOn: []string{
				"commander@2.20.0",
				"npm-path@2.0.4",
				"which@1.3.1",
			},
		},
		{
			ID: "npm@6.9.0",
			DependsOn: []string{
				"JSONStream@1.3.5",
				"abbrev@1.1.1",
				"ansicolors@0.3.2",
				"ansistyles@0.1.3",
				"aproba@2.0.0",
				"archy@1.0.0",
				"bin-links@1.1.2",
				"bluebird@3.5.4",
				"byte-size@5.0.1",
				"cacache@11.3.2",
				"call-limit@1.1.0",
				"chownr@1.1.1",
				"ci-info@2.0.0",
				"cli-columns@3.1.2",
				"cli-table3@0.5.1",
				"cmd-shim@2.0.2",
				"columnify@1.5.4",
				"config-chain@1.1.12",
				"detect-indent@5.0.0",
				"detect-newline@2.1.0",
				"dezalgo@1.0.3",
				"editor@1.0.0",
				"figgy-pudding@3.5.1",
				"find-npm-prefix@1.0.2",
				"fs-vacuum@1.2.10",
				"fs-write-stream-atomic@1.0.10",
				"gentle-fs@2.0.1",
				"glob@7.1.4",
				"graceful-fs@4.1.15",
				"has-unicode@2.0.1",
				"hosted-git-info@2.7.1",
				"iferr@1.0.2",
				"inflight@1.0.6",
				"inherits@2.0.3",
				"ini@1.3.5",
				"init-package-json@1.10.3",
				"is-cidr@3.0.0",
				"json-parse-better-errors@1.0.2",
				"lazy-property@1.0.0",
				"libcipm@3.0.3",
				"libnpm@2.0.1",
				"libnpmhook@5.0.2",
				"libnpx@10.2.0",
				"lock-verify@2.1.0",
				"lockfile@1.0.4",
				"lodash._baseuniq@4.6.0",
				"lodash.clonedeep@4.5.0",
				"lodash.union@4.6.0",
				"lodash.uniq@4.5.0",
				"lodash.without@4.4.0",
				"lru-cache@4.1.5",
				"meant@1.0.1",
				"mississippi@3.0.0",
				"mkdirp@0.5.1",
				"move-concurrently@1.0.1",
				"node-gyp@3.8.0",
				"nopt@4.0.1",
				"normalize-package-data@2.5.0",
				"npm-audit-report@1.3.2",
				"npm-cache-filename@1.0.2",
				"npm-install-checks@3.0.0",
				"npm-lifecycle@2.1.1",
				"npm-package-arg@6.1.0",
				"npm-packlist@1.4.1",
				"npm-pick-manifest@2.2.3",
				"npm-registry-fetch@3.9.0",
				"npm-user-validate@1.0.0",
				"npmlog@4.1.2",
				"once@1.4.0",
				"opener@1.5.1",
				"osenv@0.1.5",
				"pacote@9.5.0",
				"path-is-inside@1.0.2",
				"promise-inflight@1.0.1",
				"qrcode-terminal@0.12.0",
				"query-string@6.5.0",
				"qw@1.0.1",
				"read@1.0.7",
				"read-cmd-shim@1.0.1",
				"read-installed@4.0.3",
				"read-package-json@2.0.13",
				"read-package-tree@5.2.2",
				"readable-stream@3.3.0",
				"request@2.88.0",
				"retry@0.12.0",
				"rimraf@2.6.3",
				"safe-buffer@5.1.2",
				"semver@5.7.0",
				"sha@2.0.1",
				"slide@1.1.6",
				"sorted-object@2.0.1",
				"sorted-union-stream@2.1.3",
				"ssri@6.0.1",
				"stringify-package@1.0.0",
				"tar@4.4.8",
				"text-table@0.2.0",
				"tiny-relative-date@1.3.0",
				"uid-number@0.0.6",
				"umask@1.1.0",
				"unique-filename@1.1.1",
				"unpipe@1.0.0",
				"update-notifier@2.5.0",
				"uuid@3.3.2",
				"validate-npm-package-license@3.0.4",
				"validate-npm-package-name@3.0.0",
				"which@1.3.1",
				"worker-farm@1.7.0",
				"write-file-atomic@2.4.2",
			},
		},
		{
			ID: "npmlog@4.1.2",
			DependsOn: []string{
				"are-we-there-yet@1.1.5",
				"console-control-strings@1.1.0",
				"gauge@2.7.4",
				"set-blocking@2.0.0",
			},
		},
		{
			ID: "nth-check@1.0.2",
			DependsOn: []string{
				"boolbase@1.0.0",
			},
		},
		{
			ID: "object-copy@0.1.0",
			DependsOn: []string{
				"copy-descriptor@0.1.1",
				"define-property@0.2.5",
				"kind-of@3.2.2",
			},
		},
		{
			ID: "object-visit@1.0.1",
			DependsOn: []string{
				"isobject@3.0.1",
			},
		},
		{
			ID: "object.assign@4.1.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"function-bind@1.1.1",
				"has-symbols@1.0.0",
				"object-keys@1.1.1",
			},
		},
		{
			ID: "object.entries@1.1.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
				"function-bind@1.1.1",
				"has@1.0.3",
			},
		},
		{
			ID: "object.fromentries@2.0.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
				"function-bind@1.1.1",
				"has@1.0.3",
			},
		},
		{
			ID: "object.getownpropertydescriptors@2.0.3",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
			},
		},
		{
			ID: "object.omit@2.0.1",
			DependsOn: []string{
				"for-own@0.1.5",
				"is-extendable@0.1.1",
			},
		},
		{
			ID: "object.pick@1.3.0",
			DependsOn: []string{
				"isobject@3.0.1",
			},
		},
		{
			ID: "object.values@1.1.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
				"function-bind@1.1.1",
				"has@1.0.3",
			},
		},
		{
			ID: "on-finished@2.3.0",
			DependsOn: []string{
				"ee-first@1.1.1",
			},
		},
		{
			ID: "once@1.4.0",
			DependsOn: []string{
				"wrappy@1.0.2",
			},
		},
		{
			ID: "onetime@2.0.1",
			DependsOn: []string{
				"mimic-fn@1.2.0",
			},
		},
		{
			ID: "opn@5.4.0",
			DependsOn: []string{
				"is-wsl@1.1.0",
			},
		},
		{
			ID: "opn@5.5.0",
			DependsOn: []string{
				"is-wsl@1.1.0",
			},
		},
		{
			ID: "optimist@0.6.1",
			DependsOn: []string{
				"minimist@0.0.10",
				"wordwrap@0.0.3",
			},
		},
		{
			ID: "optionator@0.8.2",
			DependsOn: []string{
				"deep-is@0.1.3",
				"fast-levenshtein@2.0.6",
				"levn@0.3.0",
				"prelude-ls@1.1.2",
				"type-check@0.3.2",
				"wordwrap@1.0.0",
			},
		},
		{
			ID: "original@1.0.2",
			DependsOn: []string{
				"url-parse@1.4.7",
			},
		},
		{
			ID: "os-locale@1.4.0",
			DependsOn: []string{
				"lcid@1.0.0",
			},
		},
		{
			ID: "os-locale@2.1.0",
			DependsOn: []string{
				"execa@0.7.0",
				"lcid@1.0.0",
				"mem@1.1.0",
			},
		},
		{
			ID: "os-locale@3.1.0",
			DependsOn: []string{
				"execa@1.0.0",
				"lcid@2.0.0",
				"mem@4.3.0",
			},
		},
		{
			ID: "os-name@3.1.0",
			DependsOn: []string{
				"macos-release@2.2.0",
				"windows-release@3.2.0",
			},
		},
		{
			ID: "osenv@0.1.5",
			DependsOn: []string{
				"os-homedir@1.0.2",
				"os-tmpdir@1.0.2",
			},
		},
		{
			ID: "output-file-sync@1.1.2",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"mkdirp@0.5.1",
				"object-assign@4.1.1",
			},
		},
		{
			ID: "p-limit@1.3.0",
			DependsOn: []string{
				"p-try@1.0.0",
			},
		},
		{
			ID: "p-limit@2.2.0",
			DependsOn: []string{
				"p-try@2.2.0",
			},
		},
		{
			ID: "p-locate@2.0.0",
			DependsOn: []string{
				"p-limit@1.3.0",
			},
		},
		{
			ID: "p-locate@3.0.0",
			DependsOn: []string{
				"p-limit@2.2.0",
			},
		},
		{
			ID: "p-timeout@1.2.1",
			DependsOn: []string{
				"p-finally@1.0.0",
			},
		},
		{
			ID: "package-json@4.0.1",
			DependsOn: []string{
				"got@6.7.1",
				"registry-auth-token@3.4.0",
				"registry-url@3.1.0",
				"semver@5.7.0",
			},
		},
		{
			ID: "pacote@9.5.0",
			DependsOn: []string{
				"bluebird@3.5.4",
				"cacache@11.3.2",
				"figgy-pudding@3.5.1",
				"get-stream@4.1.0",
				"glob@7.1.4",
				"lru-cache@5.1.1",
				"make-fetch-happen@4.0.1",
				"minimatch@3.0.4",
				"minipass@2.3.5",
				"mississippi@3.0.0",
				"mkdirp@0.5.1",
				"normalize-package-data@2.5.0",
				"npm-package-arg@6.1.0",
				"npm-packlist@1.4.1",
				"npm-pick-manifest@2.2.3",
				"npm-registry-fetch@3.9.0",
				"osenv@0.1.5",
				"promise-inflight@1.0.1",
				"promise-retry@1.1.1",
				"protoduck@5.0.1",
				"rimraf@2.6.3",
				"safe-buffer@5.1.2",
				"semver@5.7.0",
				"ssri@6.0.1",
				"tar@4.4.8",
				"unique-filename@1.1.1",
				"which@1.3.1",
			},
		},
		{
			ID: "parallel-transform@1.1.0",
			DependsOn: []string{
				"cyclist@0.2.2",
				"inherits@2.0.3",
				"readable-stream@2.3.6",
			},
		},
		{
			ID: "param-case@2.1.1",
			DependsOn: []string{
				"no-case@2.3.2",
			},
		},
		{
			ID: "parent-module@1.0.1",
			DependsOn: []string{
				"callsites@3.1.0",
			},
		},
		{
			ID: "parse-asn1@5.1.4",
			DependsOn: []string{
				"asn1.js@4.10.1",
				"browserify-aes@1.2.0",
				"create-hash@1.2.0",
				"evp_bytestokey@1.0.3",
				"pbkdf2@3.0.17",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "parse-glob@3.0.4",
			DependsOn: []string{
				"glob-base@0.3.0",
				"is-dotfile@1.0.3",
				"is-extglob@1.0.0",
				"is-glob@2.0.1",
			},
		},
		{
			ID: "parse-json@2.2.0",
			DependsOn: []string{
				"error-ex@1.3.2",
			},
		},
		{
			ID: "parse-json@4.0.0",
			DependsOn: []string{
				"error-ex@1.3.2",
				"json-parse-better-errors@1.0.2",
			},
		},
		{
			ID: "parse5@3.0.3",
			DependsOn: []string{
				"@types/node@12.0.2",
			},
		},
		{
			ID: "parseqs@0.0.5",
			DependsOn: []string{
				"better-assert@1.0.2",
			},
		},
		{
			ID: "parseuri@0.0.5",
			DependsOn: []string{
				"better-assert@1.0.2",
			},
		},
		{
			ID: "path-exists@2.1.0",
			DependsOn: []string{
				"pinkie-promise@2.0.1",
			},
		},
		{
			ID: "path-to-regexp@1.7.0",
			DependsOn: []string{
				"isarray@0.0.1",
			},
		},
		{
			ID: "path-type@1.1.0",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"pify@2.3.0",
				"pinkie-promise@2.0.1",
			},
		},
		{
			ID: "path-type@2.0.0",
			DependsOn: []string{
				"pify@2.3.0",
			},
		},
		{
			ID: "path-type@3.0.0",
			DependsOn: []string{
				"pify@3.0.0",
			},
		},
		{
			ID: "path@0.12.7",
			DependsOn: []string{
				"process@0.11.10",
				"util@0.10.4",
			},
		},
		{
			ID: "pbkdf2@3.0.17",
			DependsOn: []string{
				"create-hash@1.2.0",
				"create-hmac@1.1.7",
				"ripemd160@2.0.2",
				"safe-buffer@5.1.2",
				"sha.js@2.4.11",
			},
		},
		{
			ID: "pinkie-promise@2.0.1",
			DependsOn: []string{
				"pinkie@2.0.4",
			},
		},
		{
			ID: "pirates@4.0.1",
			DependsOn: []string{
				"node-modules-regexp@1.0.0",
			},
		},
		{
			ID: "pkg-dir@1.0.0",
			DependsOn: []string{
				"find-up@1.1.2",
			},
		},
		{
			ID: "pkg-dir@2.0.0",
			DependsOn: []string{
				"find-up@2.1.0",
			},
		},
		{
			ID: "pkg-dir@3.0.0",
			DependsOn: []string{
				"find-up@3.0.0",
			},
		},
		{
			ID: "pkg-up@2.0.0",
			DependsOn: []string{
				"find-up@2.1.0",
			},
		},
		{
			ID: "please-upgrade-node@3.1.1",
			DependsOn: []string{
				"semver-compare@1.0.0",
			},
		},
		{
			ID: "portfinder@1.0.20",
			DependsOn: []string{
				"async@1.5.2",
				"debug@2.6.9",
				"mkdirp@0.5.1",
			},
		},
		{
			ID: "postcss-flexbugs-fixes@4.1.0",
			DependsOn: []string{
				"postcss@7.0.16",
			},
		},
		{
			ID: "postcss-load-config@2.0.0",
			DependsOn: []string{
				"cosmiconfig@4.0.0",
				"import-cwd@2.1.0",
			},
		},
		{
			ID: "postcss-loader@3.0.0",
			DependsOn: []string{
				"loader-utils@1.2.3",
				"postcss@7.0.16",
				"postcss-load-config@2.0.0",
				"schema-utils@1.0.0",
			},
		},
		{
			ID: "postcss-modules-extract-imports@1.2.1",
			DependsOn: []string{
				"postcss@6.0.23",
			},
		},
		{
			ID: "postcss-modules-local-by-default@1.2.0",
			DependsOn: []string{
				"css-selector-tokenizer@0.7.1",
				"postcss@6.0.23",
			},
		},
		{
			ID: "postcss-modules-scope@1.1.0",
			DependsOn: []string{
				"css-selector-tokenizer@0.7.1",
				"postcss@6.0.23",
			},
		},
		{
			ID: "postcss-modules-values@1.3.0",
			DependsOn: []string{
				"icss-replace-symbols@1.1.0",
				"postcss@6.0.23",
			},
		},
		{
			ID: "postcss@6.0.23",
			DependsOn: []string{
				"chalk@2.4.2",
				"source-map@0.6.1",
				"supports-color@5.5.0",
			},
		},
		{
			ID: "postcss@7.0.16",
			DependsOn: []string{
				"chalk@2.4.2",
				"source-map@0.6.1",
				"supports-color@6.1.0",
			},
		},
		{
			ID: "pretty-error@2.1.1",
			DependsOn: []string{
				"renderkid@2.0.3",
				"utila@0.4.0",
			},
		},
		{
			ID: "pretty-format@23.6.0",
			DependsOn: []string{
				"ansi-regex@3.0.0",
				"ansi-styles@3.2.1",
			},
		},
		{
			ID: "promise-retry@1.1.1",
			DependsOn: []string{
				"err-code@1.1.2",
				"retry@0.10.1",
			},
		},
		{
			ID: "promise.allsettled@1.0.1",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
				"function-bind@1.1.1",
			},
		},
		{
			ID: "promise.prototype.finally@3.1.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
				"function-bind@1.1.1",
			},
		},
		{
			ID: "promise@7.3.1",
			DependsOn: []string{
				"asap@2.0.6",
			},
		},
		{
			ID: "prompts@0.1.14",
			DependsOn: []string{
				"kleur@2.0.2",
				"sisteransi@0.1.1",
			},
		},
		{
			ID: "promzard@0.3.0",
			DependsOn: []string{
				"read@1.0.7",
			},
		},
		{
			ID: "prop-types-exact@1.2.0",
			DependsOn: []string{
				"has@1.0.3",
				"object.assign@4.1.0",
				"reflect.ownkeys@0.2.0",
			},
		},
		{
			ID: "prop-types@15.7.2",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"react-is@16.8.6",
			},
		},
		{
			ID: "property-information@5.1.0",
			DependsOn: []string{
				"xtend@4.0.1",
			},
		},
		{
			ID: "protoduck@5.0.1",
			DependsOn: []string{
				"genfun@5.0.0",
			},
		},
		{
			ID: "proxy-addr@2.0.5",
			DependsOn: []string{
				"forwarded@0.1.2",
				"ipaddr.js@1.9.0",
			},
		},
		{
			ID: "public-encrypt@4.0.3",
			DependsOn: []string{
				"bn.js@4.11.8",
				"browserify-rsa@4.0.1",
				"create-hash@1.2.0",
				"parse-asn1@5.1.4",
				"randombytes@2.1.0",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "pump@2.0.1",
			DependsOn: []string{
				"end-of-stream@1.4.1",
				"once@1.4.0",
			},
		},
		{
			ID: "pump@3.0.0",
			DependsOn: []string{
				"end-of-stream@1.4.1",
				"once@1.4.0",
			},
		},
		{
			ID: "pumpify@1.5.1",
			DependsOn: []string{
				"duplexify@3.7.1",
				"inherits@2.0.3",
				"pump@2.0.1",
			},
		},
		{
			ID: "query-string@6.5.0",
			DependsOn: []string{
				"decode-uri-component@0.2.0",
				"split-on-first@1.1.0",
				"strict-uri-encode@2.0.0",
			},
		},
		{
			ID: "raf@3.4.1",
			DependsOn: []string{
				"performance-now@2.1.0",
			},
		},
		{
			ID: "randexp@0.4.6",
			DependsOn: []string{
				"discontinuous-range@1.0.0",
				"ret@0.1.15",
			},
		},
		{
			ID: "randomatic@3.1.1",
			DependsOn: []string{
				"is-number@4.0.0",
				"kind-of@6.0.2",
				"math-random@1.0.4",
			},
		},
		{
			ID: "randombytes@2.1.0",
			DependsOn: []string{
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "randomfill@1.0.4",
			DependsOn: []string{
				"randombytes@2.1.0",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "raw-body@2.3.3",
			DependsOn: []string{
				"bytes@3.0.0",
				"http-errors@1.6.3",
				"iconv-lite@0.4.23",
				"unpipe@1.0.0",
			},
		},
		{
			ID: "rc@1.2.8",
			DependsOn: []string{
				"deep-extend@0.6.0",
				"ini@1.3.5",
				"minimist@1.2.0",
				"strip-json-comments@2.0.1",
			},
		},
		{
			ID: "react-addons-create-fragment@15.6.2",
			DependsOn: []string{
				"fbjs@0.8.17",
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
			},
		},
		{
			ID: "react-color@2.17.3",
			DependsOn: []string{
				"@icons/material@0.2.4",
				"lodash@4.17.11",
				"material-colors@1.2.6",
				"prop-types@15.7.2",
				"reactcss@1.2.3",
				"tinycolor2@1.4.1",
			},
		},
		{
			ID: "react-datepicker@2.5.0",
			DependsOn: []string{
				"classnames@2.2.6",
				"date-fns@2.0.0-alpha.27",
				"prop-types@15.7.2",
				"react-onclickoutside@6.8.0",
				"react-popper@1.3.3",
			},
		},
		{
			ID: "react-dev-utils@6.1.1",
			DependsOn: []string{
				"@babel/code-frame@7.0.0",
				"address@1.0.3",
				"browserslist@4.1.1",
				"chalk@2.4.1",
				"cross-spawn@6.0.5",
				"detect-port-alt@1.1.6",
				"escape-string-regexp@1.0.5",
				"filesize@3.6.1",
				"find-up@3.0.0",
				"global-modules@1.0.0",
				"globby@8.0.1",
				"gzip-size@5.0.0",
				"immer@1.7.2",
				"inquirer@6.2.0",
				"is-root@2.0.0",
				"loader-utils@1.1.0",
				"opn@5.4.0",
				"pkg-up@2.0.0",
				"react-error-overlay@5.1.6",
				"recursive-readdir@2.2.2",
				"shell-quote@1.6.1",
				"sockjs-client@1.1.5",
				"strip-ansi@4.0.0",
				"text-table@0.2.0",
			},
		},
		{
			ID: "react-docgen@3.0.0",
			DependsOn: []string{
				"@babel/parser@7.4.4",
				"@babel/runtime@7.4.4",
				"async@2.6.2",
				"commander@2.20.0",
				"doctrine@2.1.0",
				"node-dir@0.1.17",
				"recast@0.16.2",
			},
		},
		{
			ID: "react-dom@16.8.3",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"prop-types@15.7.2",
				"scheduler@0.13.6",
			},
		},
		{
			ID: "react-dom@16.8.6",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"prop-types@15.7.2",
				"scheduler@0.13.6",
			},
		},
		{
			ID: "react-dropzone@10.1.4",
			DependsOn: []string{
				"attr-accept@1.1.3",
				"file-selector@0.1.11",
				"prop-types@15.7.2",
			},
		},
		{
			ID: "react-event-listener@0.6.6",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"prop-types@15.7.2",
				"warning@4.0.3",
			},
		},
		{
			ID: "react-fuzzy@0.5.2",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"classnames@2.2.6",
				"fuse.js@3.4.4",
				"prop-types@15.7.2",
			},
		},
		{
			ID: "react-gateway@3.0.0",
			DependsOn: []string{
				"prop-types@15.7.2",
				"react-prop-types@0.4.0",
			},
		},
		{
			ID: "react-inspector@2.3.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"is-dom@1.0.9",
				"prop-types@15.7.2",
			},
		},
		{
			ID: "react-intl-universal@1.16.2",
			DependsOn: []string{
				"console-polyfill@0.3.0",
				"cookie@0.3.1",
				"escape-html@1.0.3",
				"intl@1.2.5",
				"intl-messageformat@2.2.0",
				"invariant@2.2.4",
				"is-electron@2.2.0",
				"load-script@1.0.0",
				"lodash.merge@4.6.1",
				"object-keys@1.1.1",
				"querystring@0.2.0",
			},
		},
		{
			ID: "react-modal@3.8.1",
			DependsOn: []string{
				"exenv@1.2.2",
				"prop-types@15.7.2",
				"react-lifecycles-compat@3.0.4",
				"warning@3.0.0",
			},
		},
		{
			ID: "react-popper@1.3.3",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"create-react-context@0.2.2",
				"popper.js@1.15.0",
				"prop-types@15.7.2",
				"typed-styles@0.0.7",
				"warning@4.0.3",
			},
		},
		{
			ID: "react-prop-types@0.4.0",
			DependsOn: []string{
				"warning@3.0.0",
			},
		},
		{
			ID: "react-redux@6.0.1",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"hoist-non-react-statics@3.3.0",
				"invariant@2.2.4",
				"loose-envify@1.4.0",
				"prop-types@15.7.2",
				"react-is@16.8.6",
			},
		},
		{
			ID: "react-router-dom@4.3.1",
			DependsOn: []string{
				"history@4.9.0",
				"invariant@2.2.4",
				"loose-envify@1.4.0",
				"prop-types@15.7.2",
				"react-router@4.3.1",
				"warning@4.0.3",
			},
		},
		{
			ID: "react-router@4.3.1",
			DependsOn: []string{
				"history@4.9.0",
				"hoist-non-react-statics@2.5.5",
				"invariant@2.2.4",
				"loose-envify@1.4.0",
				"path-to-regexp@1.7.0",
				"prop-types@15.7.2",
				"warning@4.0.3",
			},
		},
		{
			ID: "react-split-pane@0.1.87",
			DependsOn: []string{
				"prop-types@15.7.2",
				"react-lifecycles-compat@3.0.4",
				"react-style-proptype@3.2.2",
			},
		},
		{
			ID: "react-style-proptype@3.2.2",
			DependsOn: []string{
				"prop-types@15.7.2",
			},
		},
		{
			ID: "react-test-renderer@16.8.6",
			DependsOn: []string{
				"object-assign@4.1.1",
				"prop-types@15.7.2",
				"react-is@16.8.6",
				"scheduler@0.13.6",
			},
		},
		{
			ID: "react-textarea-autosize@7.1.0",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"prop-types@15.7.2",
			},
		},
		{
			ID: "react-transition-group@2.9.0",
			DependsOn: []string{
				"dom-helpers@3.4.0",
				"loose-envify@1.4.0",
				"prop-types@15.7.2",
				"react-lifecycles-compat@3.0.4",
			},
		},
		{
			ID: "react-treebeard@3.1.0",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"@emotion/core@0.13.1",
				"@emotion/styled@0.10.6",
				"deep-equal@1.0.1",
				"prop-types@15.7.2",
				"shallowequal@1.1.0",
				"velocity-react@1.4.3",
			},
		},
		{
			ID: "react-virtualized@9.21.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"clsx@1.0.4",
				"dom-helpers@3.4.0",
				"linear-layout-vector@0.0.1",
				"loose-envify@1.4.0",
				"prop-types@15.7.2",
				"react-lifecycles-compat@3.0.4",
			},
		},
		{
			ID: "react@16.8.3",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"prop-types@15.7.2",
				"scheduler@0.13.6",
			},
		},
		{
			ID: "react@16.8.6",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"prop-types@15.7.2",
				"scheduler@0.13.6",
			},
		},
		{
			ID: "reactcss@1.2.3",
			DependsOn: []string{
				"lodash@4.17.11",
			},
		},
		{
			ID: "read-cmd-shim@1.0.1",
			DependsOn: []string{
				"graceful-fs@4.1.15",
			},
		},
		{
			ID: "read-installed@4.0.3",
			DependsOn: []string{
				"debuglog@1.0.1",
				"read-package-json@2.0.13",
				"readdir-scoped-modules@1.0.2",
				"semver@5.7.0",
				"slide@1.1.6",
				"util-extend@1.0.3",
			},
		},
		{
			ID: "read-package-json@2.0.13",
			DependsOn: []string{
				"glob@7.1.4",
				"json-parse-better-errors@1.0.2",
				"normalize-package-data@2.5.0",
				"slash@1.0.0",
			},
		},
		{
			ID: "read-package-tree@5.2.2",
			DependsOn: []string{
				"debuglog@1.0.1",
				"dezalgo@1.0.3",
				"once@1.4.0",
				"read-package-json@2.0.13",
				"readdir-scoped-modules@1.0.2",
			},
		},
		{
			ID: "read-pkg-up@1.0.1",
			DependsOn: []string{
				"find-up@1.1.2",
				"read-pkg@1.1.0",
			},
		},
		{
			ID: "read-pkg-up@2.0.0",
			DependsOn: []string{
				"find-up@2.1.0",
				"read-pkg@2.0.0",
			},
		},
		{
			ID: "read-pkg@1.1.0",
			DependsOn: []string{
				"load-json-file@1.1.0",
				"normalize-package-data@2.5.0",
				"path-type@1.1.0",
			},
		},
		{
			ID: "read-pkg@2.0.0",
			DependsOn: []string{
				"load-json-file@2.0.0",
				"normalize-package-data@2.5.0",
				"path-type@2.0.0",
			},
		},
		{
			ID: "read-pkg@3.0.0",
			DependsOn: []string{
				"load-json-file@4.0.0",
				"normalize-package-data@2.5.0",
				"path-type@3.0.0",
			},
		},
		{
			ID: "read-pkg@4.0.1",
			DependsOn: []string{
				"normalize-package-data@2.5.0",
				"parse-json@4.0.0",
				"pify@3.0.0",
			},
		},
		{
			ID: "read@1.0.7",
			DependsOn: []string{
				"mute-stream@0.0.8",
			},
		},
		{
			ID: "readable-stream@2.3.6",
			DependsOn: []string{
				"core-util-is@1.0.2",
				"inherits@2.0.3",
				"isarray@1.0.0",
				"process-nextick-args@2.0.0",
				"safe-buffer@5.1.2",
				"string_decoder@1.1.1",
				"util-deprecate@1.0.2",
			},
		},
		{
			ID: "readable-stream@3.3.0",
			DependsOn: []string{
				"inherits@2.0.3",
				"string_decoder@1.2.0",
				"util-deprecate@1.0.2",
			},
		},
		{
			ID: "readable-stream@1.1.14",
			DependsOn: []string{
				"core-util-is@1.0.2",
				"inherits@2.0.3",
				"isarray@0.0.1",
				"string_decoder@0.10.31",
			},
		},
		{
			ID: "readable-stream@2.1.5",
			DependsOn: []string{
				"buffer-shims@1.0.0",
				"core-util-is@1.0.2",
				"inherits@2.0.3",
				"isarray@1.0.0",
				"process-nextick-args@1.0.7",
				"string_decoder@0.10.31",
				"util-deprecate@1.0.2",
			},
		},
		{
			ID: "readdir-scoped-modules@1.0.2",
			DependsOn: []string{
				"debuglog@1.0.1",
				"dezalgo@1.0.3",
				"graceful-fs@4.1.15",
				"once@1.4.0",
			},
		},
		{
			ID: "readdirp@2.2.1",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"micromatch@3.1.10",
				"readable-stream@2.3.6",
			},
		},
		{
			ID: "readline2@1.0.1",
			DependsOn: []string{
				"code-point-at@1.1.0",
				"is-fullwidth-code-point@1.0.0",
				"mute-stream@0.0.5",
			},
		},
		{
			ID: "realpath-native@1.1.0",
			DependsOn: []string{
				"util.promisify@1.0.0",
			},
		},
		{
			ID: "recast@0.14.7",
			DependsOn: []string{
				"ast-types@0.11.3",
				"esprima@4.0.1",
				"private@0.1.8",
				"source-map@0.6.1",
			},
		},
		{
			ID: "recast@0.15.5",
			DependsOn: []string{
				"ast-types@0.11.5",
				"esprima@4.0.1",
				"private@0.1.8",
				"source-map@0.6.1",
			},
		},
		{
			ID: "recast@0.16.2",
			DependsOn: []string{
				"ast-types@0.11.7",
				"esprima@4.0.1",
				"private@0.1.8",
				"source-map@0.6.1",
			},
		},
		{
			ID: "rechoir@0.6.2",
			DependsOn: []string{
				"resolve@1.10.1",
			},
		},
		{
			ID: "recompose@0.30.0",
			DependsOn: []string{
				"@babel/runtime@7.4.4",
				"change-emitter@0.1.6",
				"fbjs@0.8.17",
				"hoist-non-react-statics@2.5.5",
				"react-lifecycles-compat@3.0.4",
				"symbol-observable@1.2.0",
			},
		},
		{
			ID: "recursive-readdir@2.2.2",
			DependsOn: []string{
				"minimatch@3.0.4",
			},
		},
		{
			ID: "redux@4.0.1",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"symbol-observable@1.2.0",
			},
		},
		{
			ID: "regenerate-unicode-properties@8.1.0",
			DependsOn: []string{
				"regenerate@1.4.0",
			},
		},
		{
			ID: "regenerator-transform@0.10.1",
			DependsOn: []string{
				"babel-runtime@6.26.0",
				"babel-types@6.26.0",
				"private@0.1.8",
			},
		},
		{
			ID: "regenerator-transform@0.13.4",
			DependsOn: []string{
				"private@0.1.8",
			},
		},
		{
			ID: "regex-cache@0.4.4",
			DependsOn: []string{
				"is-equal-shallow@0.1.3",
			},
		},
		{
			ID: "regex-not@1.0.2",
			DependsOn: []string{
				"extend-shallow@3.0.2",
				"safe-regex@1.1.0",
			},
		},
		{
			ID: "regexp.prototype.flags@1.2.0",
			DependsOn: []string{
				"define-properties@1.1.3",
			},
		},
		{
			ID: "regexpu-core@1.0.0",
			DependsOn: []string{
				"regenerate@1.4.0",
				"regjsgen@0.2.0",
				"regjsparser@0.1.5",
			},
		},
		{
			ID: "regexpu-core@2.0.0",
			DependsOn: []string{
				"regenerate@1.4.0",
				"regjsgen@0.2.0",
				"regjsparser@0.1.5",
			},
		},
		{
			ID: "regexpu-core@4.5.4",
			DependsOn: []string{
				"regenerate@1.4.0",
				"regenerate-unicode-properties@8.1.0",
				"regjsgen@0.5.0",
				"regjsparser@0.6.0",
				"unicode-match-property-ecmascript@1.0.4",
				"unicode-match-property-value-ecmascript@1.1.0",
			},
		},
		{
			ID: "registry-auth-token@3.4.0",
			DependsOn: []string{
				"rc@1.2.8",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "registry-url@3.1.0",
			DependsOn: []string{
				"rc@1.2.8",
			},
		},
		{
			ID: "regjsparser@0.1.5",
			DependsOn: []string{
				"jsesc@0.5.0",
			},
		},
		{
			ID: "regjsparser@0.6.0",
			DependsOn: []string{
				"jsesc@0.5.0",
			},
		},
		{
			ID: "rehype-parse@6.0.0",
			DependsOn: []string{
				"hast-util-from-parse5@5.0.0",
				"parse5@5.1.0",
				"xtend@4.0.1",
			},
		},
		{
			ID: "renderkid@2.0.3",
			DependsOn: []string{
				"css-select@1.2.0",
				"dom-converter@0.2.0",
				"htmlparser2@3.10.1",
				"strip-ansi@3.0.1",
				"utila@0.4.0",
			},
		},
		{
			ID: "repeating@2.0.1",
			DependsOn: []string{
				"is-finite@1.0.2",
			},
		},
		{
			ID: "request-promise-core@1.1.2",
			DependsOn: []string{
				"lodash@4.17.11",
			},
		},
		{
			ID: "request-promise-native@1.0.7",
			DependsOn: []string{
				"request-promise-core@1.1.2",
				"stealthy-require@1.1.1",
				"tough-cookie@2.5.0",
			},
		},
		{
			ID: "request@2.88.0",
			DependsOn: []string{
				"aws-sign2@0.7.0",
				"aws4@1.8.0",
				"caseless@0.12.0",
				"combined-stream@1.0.8",
				"extend@3.0.2",
				"forever-agent@0.6.1",
				"form-data@2.3.3",
				"har-validator@5.1.3",
				"http-signature@1.2.0",
				"is-typedarray@1.0.0",
				"isstream@0.1.2",
				"json-stringify-safe@5.0.1",
				"mime-types@2.1.24",
				"oauth-sign@0.9.0",
				"performance-now@2.1.0",
				"qs@6.5.2",
				"safe-buffer@5.1.2",
				"tough-cookie@2.4.3",
				"tunnel-agent@0.6.0",
				"uuid@3.3.2",
			},
		},
		{
			ID: "resolve-cwd@2.0.0",
			DependsOn: []string{
				"resolve-from@3.0.0",
			},
		},
		{
			ID: "resolve-dir@1.0.1",
			DependsOn: []string{
				"expand-tilde@2.0.2",
				"global-modules@1.0.0",
			},
		},
		{
			ID: "resolve@1.10.1",
			DependsOn: []string{
				"path-parse@1.0.6",
			},
		},
		{
			ID: "restore-cursor@1.0.1",
			DependsOn: []string{
				"exit-hook@1.1.1",
				"onetime@1.1.0",
			},
		},
		{
			ID: "restore-cursor@2.0.0",
			DependsOn: []string{
				"onetime@2.0.1",
				"signal-exit@3.0.2",
			},
		},
		{
			ID: "rimraf@2.6.3",
			DependsOn: []string{
				"glob@7.1.4",
			},
		},
		{
			ID: "ripemd160@2.0.2",
			DependsOn: []string{
				"hash-base@3.0.4",
				"inherits@2.0.3",
			},
		},
		{
			ID: "rst-selector-parser@2.2.3",
			DependsOn: []string{
				"lodash.flattendeep@4.4.0",
				"nearley@2.16.0",
			},
		},
		{
			ID: "run-async@0.1.0",
			DependsOn: []string{
				"once@1.4.0",
			},
		},
		{
			ID: "run-async@2.3.0",
			DependsOn: []string{
				"is-promise@2.1.0",
			},
		},
		{
			ID: "run-queue@1.0.3",
			DependsOn: []string{
				"aproba@1.2.0",
			},
		},
		{
			ID: "rxjs@6.5.2",
			DependsOn: []string{
				"tslib@1.9.3",
			},
		},
		{
			ID: "safe-regex@1.1.0",
			DependsOn: []string{
				"ret@0.1.15",
			},
		},
		{
			ID: "sane@2.5.2",
			DependsOn: []string{
				"anymatch@2.0.0",
				"capture-exit@1.2.0",
				"exec-sh@0.2.2",
				"fb-watchman@2.0.0",
				"micromatch@3.1.10",
				"minimist@1.2.0",
				"walker@1.0.7",
				"watch@0.18.0",
			},
		},
		{
			ID: "scheduler@0.13.6",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
			},
		},
		{
			ID: "schema-utils@0.4.7",
			DependsOn: []string{
				"ajv@6.10.0",
				"ajv-keywords@3.4.0",
			},
		},
		{
			ID: "schema-utils@1.0.0",
			DependsOn: []string{
				"ajv@6.10.0",
				"ajv-errors@1.0.1",
				"ajv-keywords@3.4.0",
			},
		},
		{
			ID: "selfsigned@1.10.4",
			DependsOn: []string{
				"node-forge@0.7.5",
			},
		},
		{
			ID: "semver-diff@2.1.0",
			DependsOn: []string{
				"semver@5.7.0",
			},
		},
		{
			ID: "send@0.16.2",
			DependsOn: []string{
				"debug@2.6.9",
				"depd@1.1.2",
				"destroy@1.0.4",
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"etag@1.8.1",
				"fresh@0.5.2",
				"http-errors@1.6.3",
				"mime@1.4.1",
				"ms@2.0.0",
				"on-finished@2.3.0",
				"range-parser@1.2.1",
				"statuses@1.4.0",
			},
		},
		{
			ID: "serve-favicon@2.5.0",
			DependsOn: []string{
				"etag@1.8.1",
				"fresh@0.5.2",
				"ms@2.1.1",
				"parseurl@1.3.3",
				"safe-buffer@5.1.1",
			},
		},
		{
			ID: "serve-index@1.9.1",
			DependsOn: []string{
				"accepts@1.3.7",
				"batch@0.6.1",
				"debug@2.6.9",
				"escape-html@1.0.3",
				"http-errors@1.6.3",
				"mime-types@2.1.24",
				"parseurl@1.3.3",
			},
		},
		{
			ID: "serve-static@1.13.2",
			DependsOn: []string{
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"parseurl@1.3.3",
				"send@0.16.2",
			},
		},
		{
			ID: "set-value@0.4.3",
			DependsOn: []string{
				"extend-shallow@2.0.1",
				"is-extendable@0.1.1",
				"is-plain-object@2.0.4",
				"to-object-path@0.3.0",
			},
		},
		{
			ID: "set-value@2.0.0",
			DependsOn: []string{
				"extend-shallow@2.0.1",
				"is-extendable@0.1.1",
				"is-plain-object@2.0.4",
				"split-string@3.1.0",
			},
		},
		{
			ID: "sha.js@2.4.11",
			DependsOn: []string{
				"inherits@2.0.3",
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "sha@2.0.1",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"readable-stream@2.3.6",
			},
		},
		{
			ID: "shallow-clone@0.1.2",
			DependsOn: []string{
				"is-extendable@0.1.1",
				"kind-of@2.0.1",
				"lazy-cache@0.2.7",
				"mixin-object@2.0.1",
			},
		},
		{
			ID: "shebang-command@1.2.0",
			DependsOn: []string{
				"shebang-regex@1.0.0",
			},
		},
		{
			ID: "shell-quote@1.6.1",
			DependsOn: []string{
				"array-filter@0.0.1",
				"array-map@0.0.0",
				"array-reduce@0.0.0",
				"jsonify@0.0.0",
			},
		},
		{
			ID: "shelljs@0.8.3",
			DependsOn: []string{
				"glob@7.1.4",
				"interpret@1.2.0",
				"rechoir@0.6.2",
			},
		},
		{
			ID: "slice-ansi@1.0.0",
			DependsOn: []string{
				"is-fullwidth-code-point@2.0.0",
			},
		},
		{
			ID: "slice-ansi@2.1.0",
			DependsOn: []string{
				"ansi-styles@3.2.1",
				"astral-regex@1.0.0",
				"is-fullwidth-code-point@2.0.0",
			},
		},
		{
			ID: "snapdragon-node@2.1.1",
			DependsOn: []string{
				"define-property@1.0.0",
				"isobject@3.0.1",
				"snapdragon-util@3.0.1",
			},
		},
		{
			ID: "snapdragon-util@3.0.1",
			DependsOn: []string{
				"kind-of@3.2.2",
			},
		},
		{
			ID: "snapdragon@0.8.2",
			DependsOn: []string{
				"base@0.11.2",
				"debug@2.6.9",
				"define-property@0.2.5",
				"extend-shallow@2.0.1",
				"map-cache@0.2.2",
				"source-map@0.5.7",
				"source-map-resolve@0.5.2",
				"use@3.1.1",
			},
		},
		{
			ID: "socket.io-client@2.2.0",
			DependsOn: []string{
				"backo2@1.0.2",
				"base64-arraybuffer@0.1.5",
				"component-bind@1.0.0",
				"component-emitter@1.2.1",
				"debug@3.1.0",
				"engine.io-client@3.3.2",
				"has-binary2@1.0.3",
				"has-cors@1.1.0",
				"indexof@0.0.1",
				"object-component@0.0.3",
				"parseqs@0.0.5",
				"parseuri@0.0.5",
				"socket.io-parser@3.3.0",
				"to-array@0.1.4",
			},
		},
		{
			ID: "socket.io-parser@3.3.0",
			DependsOn: []string{
				"component-emitter@1.2.1",
				"debug@3.1.0",
				"isarray@2.0.1",
			},
		},
		{
			ID: "socket.io@2.2.0",
			DependsOn: []string{
				"debug@4.1.1",
				"engine.io@3.3.2",
				"has-binary2@1.0.3",
				"socket.io-adapter@1.1.1",
				"socket.io-client@2.2.0",
				"socket.io-parser@3.3.0",
			},
		},
		{
			ID: "sockjs-client@1.1.5",
			DependsOn: []string{
				"debug@2.6.9",
				"eventsource@0.1.6",
				"faye-websocket@0.11.1",
				"inherits@2.0.3",
				"json3@3.3.2",
				"url-parse@1.4.7",
			},
		},
		{
			ID: "sockjs-client@1.3.0",
			DependsOn: []string{
				"debug@3.2.6",
				"eventsource@1.0.7",
				"faye-websocket@0.11.1",
				"inherits@2.0.3",
				"json3@3.3.2",
				"url-parse@1.4.7",
			},
		},
		{
			ID: "sockjs@0.3.19",
			DependsOn: []string{
				"faye-websocket@0.10.0",
				"uuid@3.3.2",
			},
		},
		{
			ID: "socks-proxy-agent@4.0.2",
			DependsOn: []string{
				"agent-base@4.2.1",
				"socks@2.3.2",
			},
		},
		{
			ID: "socks@2.3.2",
			DependsOn: []string{
				"ip@1.1.5",
				"smart-buffer@4.0.2",
			},
		},
		{
			ID: "sort-keys@2.0.0",
			DependsOn: []string{
				"is-plain-obj@1.1.0",
			},
		},
		{
			ID: "sorted-union-stream@2.1.3",
			DependsOn: []string{
				"from2@1.3.0",
				"stream-iterate@1.2.0",
			},
		},
		{
			ID: "source-map-resolve@0.5.2",
			DependsOn: []string{
				"atob@2.1.2",
				"decode-uri-component@0.2.0",
				"resolve-url@0.2.1",
				"source-map-url@0.4.0",
				"urix@0.1.0",
			},
		},
		{
			ID: "source-map-support@0.4.18",
			DependsOn: []string{
				"source-map@0.5.7",
			},
		},
		{
			ID: "source-map-support@0.5.12",
			DependsOn: []string{
				"buffer-from@1.1.1",
				"source-map@0.6.1",
			},
		},
		{
			ID: "spawn-promise@0.1.8",
			DependsOn: []string{
				"co@4.6.0",
			},
		},
		{
			ID: "spdx-correct@3.1.0",
			DependsOn: []string{
				"spdx-expression-parse@3.0.0",
				"spdx-license-ids@3.0.4",
			},
		},
		{
			ID: "spdx-expression-parse@3.0.0",
			DependsOn: []string{
				"spdx-exceptions@2.2.0",
				"spdx-license-ids@3.0.4",
			},
		},
		{
			ID: "spdy-transport@3.0.0",
			DependsOn: []string{
				"debug@4.1.1",
				"detect-node@2.0.4",
				"hpack.js@2.1.6",
				"obuf@1.1.2",
				"readable-stream@3.3.0",
				"wbuf@1.7.3",
			},
		},
		{
			ID: "spdy@4.0.0",
			DependsOn: []string{
				"debug@4.1.1",
				"handle-thing@2.0.0",
				"http-deceiver@1.2.7",
				"select-hose@2.0.0",
				"spdy-transport@3.0.0",
			},
		},
		{
			ID: "split-string@3.1.0",
			DependsOn: []string{
				"extend-shallow@3.0.2",
			},
		},
		{
			ID: "sshpk@1.16.1",
			DependsOn: []string{
				"asn1@0.2.4",
				"assert-plus@1.0.0",
				"bcrypt-pbkdf@1.0.2",
				"dashdash@1.14.1",
				"ecc-jsbn@0.1.2",
				"getpass@0.1.7",
				"jsbn@0.1.1",
				"safer-buffer@2.1.2",
				"tweetnacl@0.14.5",
			},
		},
		{
			ID: "ssri@5.3.0",
			DependsOn: []string{
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "ssri@6.0.1",
			DependsOn: []string{
				"figgy-pudding@3.5.1",
			},
		},
		{
			ID: "static-extend@0.1.2",
			DependsOn: []string{
				"define-property@0.2.5",
				"object-copy@0.1.0",
			},
		},
		{
			ID: "stream-browserify@2.0.2",
			DependsOn: []string{
				"inherits@2.0.3",
				"readable-stream@2.3.6",
			},
		},
		{
			ID: "stream-each@1.2.3",
			DependsOn: []string{
				"end-of-stream@1.4.1",
				"stream-shift@1.0.0",
			},
		},
		{
			ID: "stream-http@2.8.3",
			DependsOn: []string{
				"builtin-status-codes@3.0.0",
				"inherits@2.0.3",
				"readable-stream@2.3.6",
				"to-arraybuffer@1.0.1",
				"xtend@4.0.1",
			},
		},
		{
			ID: "stream-iterate@1.2.0",
			DependsOn: []string{
				"readable-stream@2.3.6",
				"stream-shift@1.0.0",
			},
		},
		{
			ID: "string-length@2.0.0",
			DependsOn: []string{
				"astral-regex@1.0.0",
				"strip-ansi@4.0.0",
			},
		},
		{
			ID: "string-width@1.0.2",
			DependsOn: []string{
				"code-point-at@1.1.0",
				"is-fullwidth-code-point@1.0.0",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID: "string-width@2.1.1",
			DependsOn: []string{
				"is-fullwidth-code-point@2.0.0",
				"strip-ansi@4.0.0",
			},
		},
		{
			ID: "string-width@3.1.0",
			DependsOn: []string{
				"emoji-regex@7.0.3",
				"is-fullwidth-code-point@2.0.0",
				"strip-ansi@5.2.0",
			},
		},
		{
			ID: "string.prototype.matchall@3.0.1",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
				"function-bind@1.1.1",
				"has-symbols@1.0.0",
				"regexp.prototype.flags@1.2.0",
			},
		},
		{
			ID: "string.prototype.padend@3.0.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
				"function-bind@1.1.1",
			},
		},
		{
			ID: "string.prototype.padstart@3.0.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
				"function-bind@1.1.1",
			},
		},
		{
			ID: "string.prototype.trim@1.1.2",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.13.0",
				"function-bind@1.1.1",
			},
		},
		{
			ID: "string_decoder@1.2.0",
			DependsOn: []string{
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "string_decoder@1.1.1",
			DependsOn: []string{
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "stringify-object@3.3.0",
			DependsOn: []string{
				"get-own-enumerable-property-symbols@3.0.0",
				"is-obj@1.0.1",
				"is-regexp@1.0.0",
			},
		},
		{
			ID: "strip-ansi@4.0.0",
			DependsOn: []string{
				"ansi-regex@3.0.0",
			},
		},
		{
			ID: "strip-ansi@3.0.1",
			DependsOn: []string{
				"ansi-regex@2.1.1",
			},
		},
		{
			ID: "strip-ansi@5.2.0",
			DependsOn: []string{
				"ansi-regex@4.1.0",
			},
		},
		{
			ID: "strip-bom@2.0.0",
			DependsOn: []string{
				"is-utf8@0.2.1",
			},
		},
		{
			ID: "style-loader@0.23.1",
			DependsOn: []string{
				"loader-utils@1.2.3",
				"schema-utils@1.0.0",
			},
		},
		{
			ID: "styled-components@4.1.3",
			DependsOn: []string{
				"@babel/helper-module-imports@7.0.0",
				"@emotion/is-prop-valid@0.7.3",
				"@emotion/unitless@0.7.3",
				"babel-plugin-styled-components@1.10.0",
				"css-to-react-native@2.3.1",
				"memoize-one@4.1.0",
				"prop-types@15.7.2",
				"react-is@16.8.6",
				"stylis@3.5.4",
				"stylis-rule-sheet@0.0.10",
				"supports-color@5.5.0",
			},
		},
		{
			ID: "supports-color@3.2.3",
			DependsOn: []string{
				"has-flag@1.0.0",
			},
		},
		{
			ID: "supports-color@5.5.0",
			DependsOn: []string{
				"has-flag@3.0.0",
			},
		},
		{
			ID: "supports-color@6.1.0",
			DependsOn: []string{
				"has-flag@3.0.0",
			},
		},
		{
			ID: "svg-url-loader@2.3.2",
			DependsOn: []string{
				"file-loader@1.1.11",
				"loader-utils@1.1.0",
			},
		},
		{
			ID: "svgo@1.2.2",
			DependsOn: []string{
				"chalk@2.4.2",
				"coa@2.0.2",
				"css-select@2.0.2",
				"css-select-base-adapter@0.1.1",
				"css-tree@1.0.0-alpha.28",
				"css-url-regex@1.1.0",
				"csso@3.5.1",
				"js-yaml@3.13.1",
				"mkdirp@0.5.1",
				"object.values@1.1.0",
				"sax@1.2.4",
				"stable@0.1.8",
				"unquote@1.1.1",
				"util.promisify@1.0.0",
			},
		},
		{
			ID: "symbol.prototype.description@1.0.0",
			DependsOn: []string{
				"has-symbols@1.0.0",
			},
		},
		{
			ID: "table@4.0.3",
			DependsOn: []string{
				"ajv@6.10.0",
				"ajv-keywords@3.4.0",
				"chalk@2.4.2",
				"lodash@4.17.11",
				"slice-ansi@1.0.0",
				"string-width@2.1.1",
			},
		},
		{
			ID: "table@5.3.3",
			DependsOn: []string{
				"ajv@6.10.0",
				"lodash@4.17.11",
				"slice-ansi@2.1.0",
				"string-width@3.1.0",
			},
		},
		{
			ID: "tar@2.2.2",
			DependsOn: []string{
				"block-stream@0.0.9",
				"fstream@1.0.12",
				"inherits@2.0.3",
			},
		},
		{
			ID: "tar@4.4.8",
			DependsOn: []string{
				"chownr@1.1.1",
				"fs-minipass@1.2.5",
				"minipass@2.3.5",
				"minizlib@1.2.1",
				"mkdirp@0.5.1",
				"safe-buffer@5.1.2",
				"yallist@3.0.3",
			},
		},
		{
			ID: "temp@0.8.3",
			DependsOn: []string{
				"os-tmpdir@1.0.2",
				"rimraf@2.2.8",
			},
		},
		{
			ID: "term-size@1.2.0",
			DependsOn: []string{
				"execa@0.7.0",
			},
		},
		{
			ID: "terser-webpack-plugin@1.2.4",
			DependsOn: []string{
				"cacache@11.3.2",
				"find-cache-dir@2.1.0",
				"is-wsl@1.1.0",
				"schema-utils@1.0.0",
				"serialize-javascript@1.7.0",
				"source-map@0.6.1",
				"terser@3.17.0",
				"webpack-sources@1.3.0",
				"worker-farm@1.7.0",
			},
		},
		{
			ID: "terser@3.17.0",
			DependsOn: []string{
				"commander@2.20.0",
				"source-map@0.6.1",
				"source-map-support@0.5.12",
			},
		},
		{
			ID: "test-exclude@4.2.3",
			DependsOn: []string{
				"arrify@1.0.1",
				"micromatch@2.3.11",
				"object-assign@4.1.1",
				"read-pkg-up@1.0.1",
				"require-main-filename@1.0.1",
			},
		},
		{
			ID: "through2@2.0.5",
			DependsOn: []string{
				"readable-stream@2.3.6",
				"xtend@4.0.1",
			},
		},
		{
			ID: "timers-browserify@2.0.10",
			DependsOn: []string{
				"setimmediate@1.0.5",
			},
		},
		{
			ID: "tmp@0.0.33",
			DependsOn: []string{
				"os-tmpdir@1.0.2",
			},
		},
		{
			ID: "to-object-path@0.3.0",
			DependsOn: []string{
				"kind-of@3.2.2",
			},
		},
		{
			ID: "to-regex-range@2.1.1",
			DependsOn: []string{
				"is-number@3.0.0",
				"repeat-string@1.6.1",
			},
		},
		{
			ID: "to-regex@3.0.2",
			DependsOn: []string{
				"define-property@2.0.2",
				"extend-shallow@3.0.2",
				"regex-not@1.0.2",
				"safe-regex@1.1.0",
			},
		},
		{
			ID: "tough-cookie@2.5.0",
			DependsOn: []string{
				"psl@1.1.31",
				"punycode@2.1.1",
			},
		},
		{
			ID: "tough-cookie@2.4.3",
			DependsOn: []string{
				"psl@1.1.31",
				"punycode@1.4.1",
			},
		},
		{
			ID: "tr46@1.0.1",
			DependsOn: []string{
				"punycode@2.1.1",
			},
		},
		{
			ID: "tunnel-agent@0.6.0",
			DependsOn: []string{
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "type-check@0.3.2",
			DependsOn: []string{
				"prelude-ls@1.1.2",
			},
		},
		{
			ID: "type-is@1.6.18",
			DependsOn: []string{
				"media-typer@0.3.0",
				"mime-types@2.1.24",
			},
		},
		{
			ID: "uglify-js@3.4.10",
			DependsOn: []string{
				"commander@2.19.0",
				"source-map@0.6.1",
			},
		},
		{
			ID: "uglify-js@3.5.12",
			DependsOn: []string{
				"commander@2.20.0",
				"source-map@0.6.1",
			},
		},
		{
			ID: "unicode-match-property-ecmascript@1.0.4",
			DependsOn: []string{
				"unicode-canonical-property-names-ecmascript@1.0.4",
				"unicode-property-aliases-ecmascript@1.0.5",
			},
		},
		{
			ID: "unified@7.1.0",
			DependsOn: []string{
				"@types/unist@2.0.3",
				"@types/vfile@3.0.2",
				"bail@1.0.4",
				"extend@3.0.2",
				"is-plain-obj@1.1.0",
				"trough@1.0.4",
				"vfile@3.0.1",
				"x-is-string@0.1.0",
			},
		},
		{
			ID: "union-value@1.0.0",
			DependsOn: []string{
				"arr-union@3.1.0",
				"get-value@2.0.6",
				"is-extendable@0.1.1",
				"set-value@0.4.3",
			},
		},
		{
			ID: "unique-filename@1.1.1",
			DependsOn: []string{
				"unique-slug@2.0.1",
			},
		},
		{
			ID: "unique-slug@2.0.1",
			DependsOn: []string{
				"imurmurhash@0.1.4",
			},
		},
		{
			ID: "unique-string@1.0.0",
			DependsOn: []string{
				"crypto-random-string@1.0.0",
			},
		},
		{
			ID: "unist-util-stringify-position@2.0.0",
			DependsOn: []string{
				"@types/unist@2.0.3",
			},
		},
		{
			ID: "universal-user-agent@2.1.0",
			DependsOn: []string{
				"os-name@3.1.0",
			},
		},
		{
			ID: "unset-value@1.0.0",
			DependsOn: []string{
				"has-value@0.3.1",
				"isobject@3.0.1",
			},
		},
		{
			ID: "unzipper@0.8.14",
			DependsOn: []string{
				"big-integer@1.6.43",
				"binary@0.3.0",
				"bluebird@3.4.7",
				"buffer-indexof-polyfill@1.0.1",
				"duplexer2@0.1.4",
				"fstream@1.0.12",
				"listenercount@1.0.1",
				"readable-stream@2.1.5",
				"setimmediate@1.0.5",
			},
		},
		{
			ID: "update-notifier@2.5.0",
			DependsOn: []string{
				"boxen@1.3.0",
				"chalk@2.4.2",
				"configstore@3.1.2",
				"import-lazy@2.1.0",
				"is-ci@1.2.1",
				"is-installed-globally@0.1.0",
				"is-npm@1.0.0",
				"latest-version@3.1.0",
				"semver-diff@2.1.0",
				"xdg-basedir@3.0.0",
			},
		},
		{
			ID: "uri-js@4.2.2",
			DependsOn: []string{
				"punycode@2.1.1",
			},
		},
		{
			ID: "url-loader@1.1.2",
			DependsOn: []string{
				"loader-utils@1.2.3",
				"mime@2.4.2",
				"schema-utils@1.0.0",
			},
		},
		{
			ID: "url-parse-lax@1.0.0",
			DependsOn: []string{
				"prepend-http@1.0.4",
			},
		},
		{
			ID: "url-parse@1.4.7",
			DependsOn: []string{
				"querystringify@2.1.1",
				"requires-port@1.0.0",
			},
		},
		{
			ID: "url@0.11.0",
			DependsOn: []string{
				"punycode@1.3.2",
				"querystring@0.2.0",
			},
		},
		{
			ID: "util.promisify@1.0.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"object.getownpropertydescriptors@2.0.3",
			},
		},
		{
			ID: "util@0.10.3",
			DependsOn: []string{
				"inherits@2.0.1",
			},
		},
		{
			ID: "util@0.10.4",
			DependsOn: []string{
				"inherits@2.0.3",
			},
		},
		{
			ID: "util@0.11.1",
			DependsOn: []string{
				"inherits@2.0.3",
			},
		},
		{
			ID: "v8flags@2.1.1",
			DependsOn: []string{
				"user-home@1.1.1",
			},
		},
		{
			ID: "validate-npm-package-license@3.0.4",
			DependsOn: []string{
				"spdx-correct@3.1.0",
				"spdx-expression-parse@3.0.0",
			},
		},
		{
			ID: "validate-npm-package-name@3.0.0",
			DependsOn: []string{
				"builtins@1.0.3",
			},
		},
		{
			ID: "velocity-react@1.4.3",
			DependsOn: []string{
				"lodash@4.17.11",
				"prop-types@15.7.2",
				"react-transition-group@2.9.0",
				"velocity-animate@1.5.2",
			},
		},
		{
			ID: "verror@1.10.0",
			DependsOn: []string{
				"assert-plus@1.0.0",
				"core-util-is@1.0.2",
				"extsprintf@1.4.0",
			},
		},
		{
			ID: "vfile-message@1.1.1",
			DependsOn: []string{
				"unist-util-stringify-position@1.1.2",
			},
		},
		{
			ID: "vfile-message@2.0.0",
			DependsOn: []string{
				"@types/unist@2.0.3",
				"unist-util-stringify-position@1.1.2",
			},
		},
		{
			ID: "vfile@3.0.1",
			DependsOn: []string{
				"is-buffer@2.0.3",
				"replace-ext@1.0.0",
				"unist-util-stringify-position@1.1.2",
				"vfile-message@1.1.1",
			},
		},
		{
			ID: "vfile@4.0.0",
			DependsOn: []string{
				"@types/unist@2.0.3",
				"is-buffer@2.0.3",
				"replace-ext@1.0.0",
				"unist-util-stringify-position@2.0.0",
				"vfile-message@2.0.0",
			},
		},
		{
			ID: "vm-browserify@0.0.4",
			DependsOn: []string{
				"indexof@0.0.1",
			},
		},
		{
			ID: "w3c-hr-time@1.0.1",
			DependsOn: []string{
				"browser-process-hrtime@0.1.3",
			},
		},
		{
			ID: "walker@1.0.7",
			DependsOn: []string{
				"makeerror@1.0.11",
			},
		},
		{
			ID: "warning@3.0.0",
			DependsOn: []string{
				"loose-envify@1.4.0",
			},
		},
		{
			ID: "warning@4.0.3",
			DependsOn: []string{
				"loose-envify@1.4.0",
			},
		},
		{
			ID: "watch@0.18.0",
			DependsOn: []string{
				"exec-sh@0.2.2",
				"minimist@1.2.0",
			},
		},
		{
			ID: "watchpack@1.6.0",
			DependsOn: []string{
				"chokidar@2.1.5",
				"graceful-fs@4.1.15",
				"neo-async@2.6.1",
			},
		},
		{
			ID: "wbuf@1.7.3",
			DependsOn: []string{
				"minimalistic-assert@1.0.1",
			},
		},
		{
			ID: "wcwidth@1.0.1",
			DependsOn: []string{
				"defaults@1.0.3",
			},
		},
		{
			ID: "webpack-bundle-analyzer@3.3.2",
			DependsOn: []string{
				"acorn@6.1.1",
				"acorn-walk@6.1.1",
				"bfj@6.1.1",
				"chalk@2.4.2",
				"commander@2.20.0",
				"ejs@2.6.1",
				"express@4.16.4",
				"filesize@3.6.1",
				"gzip-size@5.1.0",
				"lodash@4.17.11",
				"mkdirp@0.5.1",
				"opener@1.5.1",
				"ws@6.2.1",
			},
		},
		{
			ID: "webpack-cli@3.3.2",
			DependsOn: []string{
				"chalk@2.4.2",
				"cross-spawn@6.0.5",
				"enhanced-resolve@4.1.0",
				"findup-sync@2.0.0",
				"global-modules@1.0.0",
				"import-local@2.0.0",
				"interpret@1.2.0",
				"loader-utils@1.2.3",
				"supports-color@5.5.0",
				"v8-compile-cache@2.0.3",
				"yargs@12.0.5",
			},
		},
		{
			ID: "webpack-dev-middleware@3.7.0",
			DependsOn: []string{
				"memory-fs@0.4.1",
				"mime@2.4.2",
				"range-parser@1.2.1",
				"webpack-log@2.0.0",
			},
		},
		{
			ID: "webpack-dev-server@3.3.1",
			DependsOn: []string{
				"ansi-html@0.0.7",
				"bonjour@3.5.0",
				"chokidar@2.1.5",
				"compression@1.7.4",
				"connect-history-api-fallback@1.6.0",
				"debug@4.1.1",
				"del@4.1.1",
				"express@4.16.4",
				"html-entities@1.2.1",
				"http-proxy-middleware@0.19.1",
				"import-local@2.0.0",
				"internal-ip@4.3.0",
				"ip@1.1.5",
				"killable@1.0.1",
				"loglevel@1.6.1",
				"opn@5.5.0",
				"portfinder@1.0.20",
				"schema-utils@1.0.0",
				"selfsigned@1.10.4",
				"semver@6.0.0",
				"serve-index@1.9.1",
				"sockjs@0.3.19",
				"sockjs-client@1.3.0",
				"spdy@4.0.0",
				"strip-ansi@3.0.1",
				"supports-color@6.1.0",
				"url@0.11.0",
				"webpack-dev-middleware@3.7.0",
				"webpack-log@2.0.0",
				"yargs@12.0.5",
			},
		},
		{
			ID: "webpack-hot-middleware@2.25.0",
			DependsOn: []string{
				"ansi-html@0.0.7",
				"html-entities@1.2.1",
				"querystring@0.2.0",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID: "webpack-log@2.0.0",
			DependsOn: []string{
				"ansi-colors@3.2.4",
				"uuid@3.3.2",
			},
		},
		{
			ID: "webpack-merge@4.2.1",
			DependsOn: []string{
				"lodash@4.17.11",
			},
		},
		{
			ID: "webpack-sources@1.3.0",
			DependsOn: []string{
				"source-list-map@2.0.1",
				"source-map@0.6.1",
			},
		},
		{
			ID: "webpack@4.31.0",
			DependsOn: []string{
				"@webassemblyjs/ast@1.8.5",
				"@webassemblyjs/helper-module-context@1.8.5",
				"@webassemblyjs/wasm-edit@1.8.5",
				"@webassemblyjs/wasm-parser@1.8.5",
				"acorn@6.1.1",
				"acorn-dynamic-import@4.0.0",
				"ajv@6.10.0",
				"ajv-keywords@3.4.0",
				"chrome-trace-event@1.0.0",
				"enhanced-resolve@4.1.0",
				"eslint-scope@4.0.3",
				"json-parse-better-errors@1.0.2",
				"loader-runner@2.4.0",
				"loader-utils@1.2.3",
				"memory-fs@0.4.1",
				"micromatch@3.1.10",
				"mkdirp@0.5.1",
				"neo-async@2.6.1",
				"node-libs-browser@2.2.0",
				"schema-utils@1.0.0",
				"tapable@1.1.3",
				"terser-webpack-plugin@1.2.4",
				"watchpack@1.6.0",
				"webpack-sources@1.3.0",
			},
		},
		{
			ID: "websocket-driver@0.7.0",
			DependsOn: []string{
				"http-parser-js@0.5.0",
				"websocket-extensions@0.1.3",
			},
		},
		{
			ID: "whatwg-encoding@1.0.5",
			DependsOn: []string{
				"iconv-lite@0.4.24",
			},
		},
		{
			ID: "whatwg-url@6.5.0",
			DependsOn: []string{
				"lodash.sortby@4.7.0",
				"tr46@1.0.1",
				"webidl-conversions@4.0.2",
			},
		},
		{
			ID: "whatwg-url@7.0.0",
			DependsOn: []string{
				"lodash.sortby@4.7.0",
				"tr46@1.0.1",
				"webidl-conversions@4.0.2",
			},
		},
		{
			ID: "which@1.3.1",
			DependsOn: []string{
				"isexe@2.0.0",
			},
		},
		{
			ID: "wide-align@1.1.3",
			DependsOn: []string{
				"string-width@2.1.1",
			},
		},
		{
			ID: "widest-line@2.0.1",
			DependsOn: []string{
				"string-width@2.1.1",
			},
		},
		{
			ID: "windows-release@3.2.0",
			DependsOn: []string{
				"execa@1.0.0",
			},
		},
		{
			ID: "worker-farm@1.7.0",
			DependsOn: []string{
				"errno@0.1.7",
			},
		},
		{
			ID: "wrap-ansi@2.1.0",
			DependsOn: []string{
				"string-width@1.0.2",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID: "wrap-ansi@3.0.1",
			DependsOn: []string{
				"string-width@2.1.1",
				"strip-ansi@4.0.0",
			},
		},
		{
			ID: "write-file-atomic@1.3.4",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"imurmurhash@0.1.4",
				"slide@1.1.6",
			},
		},
		{
			ID: "write-file-atomic@2.4.2",
			DependsOn: []string{
				"graceful-fs@4.1.15",
				"imurmurhash@0.1.4",
				"signal-exit@3.0.2",
			},
		},
		{
			ID: "write-json-file@2.3.0",
			DependsOn: []string{
				"detect-indent@5.0.0",
				"graceful-fs@4.1.15",
				"make-dir@1.3.0",
				"pify@3.0.0",
				"sort-keys@2.0.0",
				"write-file-atomic@2.4.2",
			},
		},
		{
			ID: "write@1.0.3",
			DependsOn: []string{
				"mkdirp@0.5.1",
			},
		},
		{
			ID: "ws@5.2.2",
			DependsOn: []string{
				"async-limiter@1.0.0",
			},
		},
		{
			ID: "ws@6.2.1",
			DependsOn: []string{
				"async-limiter@1.0.0",
			},
		},
		{
			ID: "ws@6.1.4",
			DependsOn: []string{
				"async-limiter@1.0.0",
			},
		},
		{
			ID: "yargs-parser@11.1.1",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
			},
		},
		{
			ID: "yargs-parser@2.4.1",
			DependsOn: []string{
				"camelcase@3.0.0",
				"lodash.assign@4.2.0",
			},
		},
		{
			ID: "yargs-parser@9.0.2",
			DependsOn: []string{
				"camelcase@4.1.0",
			},
		},
		{
			ID: "yargs@12.0.5",
			DependsOn: []string{
				"cliui@4.1.0",
				"decamelize@1.2.0",
				"find-up@3.0.0",
				"get-caller-file@1.0.3",
				"os-locale@3.1.0",
				"require-directory@2.1.1",
				"require-main-filename@1.0.1",
				"set-blocking@2.0.0",
				"string-width@2.1.1",
				"which-module@2.0.0",
				"y18n@4.0.0",
				"yargs-parser@11.1.1",
			},
		},
		{
			ID: "yargs@11.1.0",
			DependsOn: []string{
				"cliui@4.1.0",
				"decamelize@1.2.0",
				"find-up@2.1.0",
				"get-caller-file@1.0.3",
				"os-locale@2.1.0",
				"require-directory@2.1.1",
				"require-main-filename@1.0.1",
				"set-blocking@2.0.0",
				"string-width@2.1.1",
				"which-module@2.0.0",
				"y18n@3.2.1",
				"yargs-parser@9.0.2",
			},
		},
		{
			ID: "yargs@4.8.1",
			DependsOn: []string{
				"cliui@3.2.0",
				"decamelize@1.2.0",
				"get-caller-file@1.0.3",
				"lodash.assign@4.2.0",
				"os-locale@1.4.0",
				"read-pkg-up@1.0.1",
				"require-directory@2.1.1",
				"require-main-filename@1.0.1",
				"set-blocking@2.0.0",
				"string-width@1.0.2",
				"which-module@1.0.0",
				"window-size@0.2.0",
				"y18n@3.2.1",
				"yargs-parser@2.4.1",
			},
		},
	}

	// docker run --name yarn2 --rm -it -w /code node:12-alpine sh
	// yarn set version berry
	// apk add git
	// yarn init
	// yarn add promise jquery
	// yarn info --recursive --dependents --json | jq -r .value | grep -v workspace | awk -F'[@:]' '{printf("{\""$1"\", \""$3"\", \"\"},\n")}'
	// to get deps with locations from lock file use following commands:
	// awk '/^\S+@[~^*]?(>= )?[0-9.]*/,/^$/{if($0=="") {print "--"prev} else { if(substr($0,1,2)!="  ") {print NR":"$0} else {print $0}} prev=NR}; END{print "--"prev}' | awk 'BEGIN {s=""}; {(substr($0,1,2)=="--") ? (s=s$0"\n") : (s=s$0)}; END { print s}' | sed -E 's/@([0-9~><*\^]|npm).*version:? "?/:/' | sed 's/  /:/' | sed 's/"//g'| awk 'match($0, /[[:digit:]]+$/) {print substr($0, RSTART, RLENGTH)":"$0 }' |  awk -F":" '{print "{ID: \""$3"@"$4"\", Name: \""$3"\", Version: \""$4"\", Locations: []types.Location{{StartLine: "$2", EndLine: "$1"}}},"}'
	// and remove 'code@workspace' dependency
	yarnV2Normal = []types.Library{
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Locations: []types.Location{{StartLine: 8, EndLine: 13}}},
		{ID: "jquery@3.5.1", Name: "jquery", Version: "3.5.1", Locations: []types.Location{{StartLine: 24, EndLine: 29}}},
		{ID: "promise@8.1.0", Name: "promise", Version: "8.1.0", Locations: []types.Location{{StartLine: 31, EndLine: 38}}},
	}

	// ... and
	// node test_deps_generator/index.js yarn.lock
	yarnV2NormalDeps = []types.Dependency{
		{
			ID: "promise@8.1.0",
			DependsOn: []string{
				"asap@2.0.6",
			},
		},
	}

	// ... and
	// yarn add react redux
	// yarn info --recursive --dependents --json | jq -r .value | grep -v workspace | awk -F'[@:]' '{printf("{\""$1"\", \""$3"\", \"\"},\n")}'
	// to get deps with locations from lock file use following commands:
	// awk '/^\S+@[~^*]?(>= )?[0-9.]*/,/^$/{if($0=="") {print "--"prev} else { if(substr($0,1,2)!="  ") {print NR":"$0} else {print $0}} prev=NR}; END{print "--"prev}' | awk 'BEGIN {s=""}; {(substr($0,1,2)=="--") ? (s=s$0"\n") : (s=s$0)}; END { print s}' | sed -E 's/@([0-9~><*\^]|npm).*version:? "?/:/' | sed 's/  /:/' | sed 's/"//g'| awk 'match($0, /[[:digit:]]+$/) {print substr($0, RSTART, RLENGTH)":"$0 }' |  awk -F":" '{print "{ID: \""$3"@"$4"\", Name: \""$3"\", Version: \""$4"\", Locations: []types.Location{{StartLine: "$2", EndLine: "$1"}}},"}'
	// and remove 'code@workspace' and 'fsevents@patch' dependencies
	yarnV2React = []types.Library{
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Locations: []types.Location{{StartLine: 8, EndLine: 13}}},
		{ID: "jquery@3.5.1", Name: "jquery", Version: "3.5.1", Locations: []types.Location{{StartLine: 26, EndLine: 31}}},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Locations: []types.Location{{StartLine: 33, EndLine: 38}}},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Locations: []types.Location{{StartLine: 40, EndLine: 49}}},
		{ID: "object-assign@4.1.1", Name: "object-assign", Version: "4.1.1", Locations: []types.Location{{StartLine: 51, EndLine: 56}}},
		{ID: "promise@8.1.0", Name: "promise", Version: "8.1.0", Locations: []types.Location{{StartLine: 58, EndLine: 65}}},
		{ID: "prop-types@15.7.2", Name: "prop-types", Version: "15.7.2", Locations: []types.Location{{StartLine: 67, EndLine: 76}}},
		{ID: "react-is@16.13.1", Name: "react-is", Version: "16.13.1", Locations: []types.Location{{StartLine: 78, EndLine: 83}}},
		{ID: "react@16.13.1", Name: "react", Version: "16.13.1", Locations: []types.Location{{StartLine: 85, EndLine: 94}}},
		{ID: "redux@4.0.5", Name: "redux", Version: "4.0.5", Locations: []types.Location{{StartLine: 96, EndLine: 104}}},
		{ID: "symbol-observable@1.2.0", Name: "symbol-observable", Version: "1.2.0", Locations: []types.Location{{StartLine: 106, EndLine: 111}}},
	}

	// ... and
	// node test_deps_generator/index.js yarn.lock
	yarnV2ReactDeps = []types.Dependency{
		{
			ID: "promise@8.1.0",
			DependsOn: []string{
				"asap@2.0.6",
			},
		},
		{
			ID: "loose-envify@1.4.0",
			DependsOn: []string{
				"js-tokens@4.0.0",
			},
		},
		{
			ID: "react@16.13.1",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"prop-types@15.7.2",
			},
		},
		{
			ID: "prop-types@15.7.2",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"react-is@16.13.1",
			},
		},
		{
			ID: "redux@4.0.5",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"symbol-observable@1.2.0",
			},
		},
	}

	// ... and
	// yarn add -D mocha
	// yarn info --recursive --dependents --json | jq -r .value | grep -v workspace | awk -F'[@:]' '{printf("{\""$1"\", \""$3"\", \"\"},\n")}'
	// to get deps with locations from lock file use following commands:
	// awk '/^\S+@[~^*]?(>= )?[0-9.]*/,/^$/{if($0=="") {print "--"prev} else { if(substr($0,1,2)!="  ") {print NR":"$0} else {print $0}} prev=NR}; END{print "--"prev}' | awk 'BEGIN {s=""}; {(substr($0,1,2)=="--") ? (s=s$0"\n") : (s=s$0)}; END { print s}' | sed -E 's/@([0-9~><*\^]|npm).*version:? "?/:/' | sed 's/  /:/' | sed 's/"//g'| awk 'match($0, /[[:digit:]]+$/) {print substr($0, RSTART, RLENGTH)":"$0 }' |  awk -F":" '{print "{ID: \""$3"@"$4"\", Name: \""$3"\", Version: \""$4"\", Locations: []types.Location{{StartLine: "$2", EndLine: "$1"}}},"}'
	// and remove 'code@workspace' and 'fsevents@patch' dependencies
	yarnV2WithDev = []types.Library{
		{ID: "@types/color-name@1.1.1", Name: "@types/color-name", Version: "1.1.1", Locations: []types.Location{{StartLine: 8, EndLine: 13}}},
		{ID: "abbrev@1.1.1", Name: "abbrev", Version: "1.1.1", Locations: []types.Location{{StartLine: 15, EndLine: 20}}},
		{ID: "ajv@6.12.4", Name: "ajv", Version: "6.12.4", Locations: []types.Location{{StartLine: 22, EndLine: 32}}},
		{ID: "ansi-colors@4.1.1", Name: "ansi-colors", Version: "4.1.1", Locations: []types.Location{{StartLine: 34, EndLine: 39}}},
		{ID: "ansi-regex@2.1.1", Name: "ansi-regex", Version: "2.1.1", Locations: []types.Location{{StartLine: 41, EndLine: 46}}},
		{ID: "ansi-regex@3.0.0", Name: "ansi-regex", Version: "3.0.0", Locations: []types.Location{{StartLine: 48, EndLine: 53}}},
		{ID: "ansi-regex@4.1.0", Name: "ansi-regex", Version: "4.1.0", Locations: []types.Location{{StartLine: 55, EndLine: 60}}},
		{ID: "ansi-styles@3.2.1", Name: "ansi-styles", Version: "3.2.1", Locations: []types.Location{{StartLine: 62, EndLine: 69}}},
		{ID: "ansi-styles@4.2.1", Name: "ansi-styles", Version: "4.2.1", Locations: []types.Location{{StartLine: 71, EndLine: 79}}},
		{ID: "anymatch@3.1.1", Name: "anymatch", Version: "3.1.1", Locations: []types.Location{{StartLine: 81, EndLine: 89}}},
		{ID: "aproba@1.2.0", Name: "aproba", Version: "1.2.0", Locations: []types.Location{{StartLine: 91, EndLine: 96}}},
		{ID: "are-we-there-yet@1.1.5", Name: "are-we-there-yet", Version: "1.1.5", Locations: []types.Location{{StartLine: 98, EndLine: 106}}},
		{ID: "argparse@1.0.10", Name: "argparse", Version: "1.0.10", Locations: []types.Location{{StartLine: 108, EndLine: 115}}},
		{ID: "array.prototype.map@1.0.2", Name: "array.prototype.map", Version: "1.0.2", Locations: []types.Location{{StartLine: 117, EndLine: 127}}},
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Locations: []types.Location{{StartLine: 129, EndLine: 134}}},
		{ID: "asn1@0.2.4", Name: "asn1", Version: "0.2.4", Locations: []types.Location{{StartLine: 136, EndLine: 143}}},
		{ID: "assert-plus@1.0.0", Name: "assert-plus", Version: "1.0.0", Locations: []types.Location{{StartLine: 145, EndLine: 150}}},
		{ID: "asynckit@0.4.0", Name: "asynckit", Version: "0.4.0", Locations: []types.Location{{StartLine: 152, EndLine: 157}}},
		{ID: "aws-sign2@0.7.0", Name: "aws-sign2", Version: "0.7.0", Locations: []types.Location{{StartLine: 159, EndLine: 164}}},
		{ID: "aws4@1.10.1", Name: "aws4", Version: "1.10.1", Locations: []types.Location{{StartLine: 166, EndLine: 171}}},
		{ID: "balanced-match@1.0.0", Name: "balanced-match", Version: "1.0.0", Locations: []types.Location{{StartLine: 173, EndLine: 178}}},
		{ID: "bcrypt-pbkdf@1.0.2", Name: "bcrypt-pbkdf", Version: "1.0.2", Locations: []types.Location{{StartLine: 180, EndLine: 187}}},
		{ID: "binary-extensions@2.1.0", Name: "binary-extensions", Version: "2.1.0", Locations: []types.Location{{StartLine: 189, EndLine: 194}}},
		{ID: "brace-expansion@1.1.11", Name: "brace-expansion", Version: "1.1.11", Locations: []types.Location{{StartLine: 196, EndLine: 204}}},
		{ID: "braces@3.0.2", Name: "braces", Version: "3.0.2", Locations: []types.Location{{StartLine: 206, EndLine: 213}}},
		{ID: "browser-stdout@1.3.1", Name: "browser-stdout", Version: "1.3.1", Locations: []types.Location{{StartLine: 215, EndLine: 220}}},
		{ID: "camelcase@5.3.1", Name: "camelcase", Version: "5.3.1", Locations: []types.Location{{StartLine: 222, EndLine: 227}}},
		{ID: "caseless@0.12.0", Name: "caseless", Version: "0.12.0", Locations: []types.Location{{StartLine: 229, EndLine: 234}}},
		{ID: "chalk@4.1.0", Name: "chalk", Version: "4.1.0", Locations: []types.Location{{StartLine: 236, EndLine: 244}}},
		{ID: "chokidar@3.4.2", Name: "chokidar", Version: "3.4.2", Locations: []types.Location{{StartLine: 246, EndLine: 263}}},
		{ID: "chownr@2.0.0", Name: "chownr", Version: "2.0.0", Locations: []types.Location{{StartLine: 265, EndLine: 270}}},
		{ID: "cliui@5.0.0", Name: "cliui", Version: "5.0.0", Locations: []types.Location{{StartLine: 272, EndLine: 281}}},
		{ID: "code-point-at@1.1.0", Name: "code-point-at", Version: "1.1.0", Locations: []types.Location{{StartLine: 283, EndLine: 288}}},
		{ID: "color-convert@1.9.3", Name: "color-convert", Version: "1.9.3", Locations: []types.Location{{StartLine: 302, EndLine: 309}}},
		{ID: "color-convert@2.0.1", Name: "color-convert", Version: "2.0.1", Locations: []types.Location{{StartLine: 311, EndLine: 318}}},
		{ID: "color-name@1.1.3", Name: "color-name", Version: "1.1.3", Locations: []types.Location{{StartLine: 320, EndLine: 325}}},
		{ID: "color-name@1.1.4", Name: "color-name", Version: "1.1.4", Locations: []types.Location{{StartLine: 327, EndLine: 332}}},
		{ID: "combined-stream@1.0.8", Name: "combined-stream", Version: "1.0.8", Locations: []types.Location{{StartLine: 334, EndLine: 341}}},
		{ID: "concat-map@0.0.1", Name: "concat-map", Version: "0.0.1", Locations: []types.Location{{StartLine: 343, EndLine: 348}}},
		{ID: "console-control-strings@1.1.0", Name: "console-control-strings", Version: "1.1.0", Locations: []types.Location{{StartLine: 350, EndLine: 355}}},
		{ID: "core-util-is@1.0.2", Name: "core-util-is", Version: "1.0.2", Locations: []types.Location{{StartLine: 357, EndLine: 362}}},
		{ID: "dashdash@1.14.1", Name: "dashdash", Version: "1.14.1", Locations: []types.Location{{StartLine: 364, EndLine: 371}}},
		{ID: "debug@4.1.1", Name: "debug", Version: "4.1.1", Locations: []types.Location{{StartLine: 373, EndLine: 380}}},
		{ID: "decamelize@1.2.0", Name: "decamelize", Version: "1.2.0", Locations: []types.Location{{StartLine: 382, EndLine: 387}}},
		{ID: "define-properties@1.1.3", Name: "define-properties", Version: "1.1.3", Locations: []types.Location{{StartLine: 389, EndLine: 396}}},
		{ID: "delayed-stream@1.0.0", Name: "delayed-stream", Version: "1.0.0", Locations: []types.Location{{StartLine: 398, EndLine: 403}}},
		{ID: "delegates@1.0.0", Name: "delegates", Version: "1.0.0", Locations: []types.Location{{StartLine: 405, EndLine: 410}}},
		{ID: "diff@4.0.2", Name: "diff", Version: "4.0.2", Locations: []types.Location{{StartLine: 412, EndLine: 417}}},
		{ID: "ecc-jsbn@0.1.2", Name: "ecc-jsbn", Version: "0.1.2", Locations: []types.Location{{StartLine: 419, EndLine: 427}}},
		{ID: "emoji-regex@7.0.3", Name: "emoji-regex", Version: "7.0.3", Locations: []types.Location{{StartLine: 429, EndLine: 434}}},
		{ID: "env-paths@2.2.0", Name: "env-paths", Version: "2.2.0", Locations: []types.Location{{StartLine: 436, EndLine: 441}}},
		{ID: "es-abstract@1.17.6", Name: "es-abstract", Version: "1.17.6", Locations: []types.Location{{StartLine: 443, EndLine: 460}}},
		{ID: "es-array-method-boxes-properly@1.0.0", Name: "es-array-method-boxes-properly", Version: "1.0.0", Locations: []types.Location{{StartLine: 462, EndLine: 467}}},
		{ID: "es-get-iterator@1.1.0", Name: "es-get-iterator", Version: "1.1.0", Locations: []types.Location{{StartLine: 469, EndLine: 482}}},
		{ID: "es-to-primitive@1.2.1", Name: "es-to-primitive", Version: "1.2.1", Locations: []types.Location{{StartLine: 484, EndLine: 493}}},
		{ID: "escape-string-regexp@4.0.0", Name: "escape-string-regexp", Version: "4.0.0", Locations: []types.Location{{StartLine: 495, EndLine: 500}}},
		{ID: "esprima@4.0.1", Name: "esprima", Version: "4.0.1", Locations: []types.Location{{StartLine: 502, EndLine: 510}}},
		{ID: "extend@3.0.2", Name: "extend", Version: "3.0.2", Locations: []types.Location{{StartLine: 512, EndLine: 517}}},
		{ID: "extsprintf@1.3.0", Name: "extsprintf", Version: "1.3.0", Locations: []types.Location{{StartLine: 519, EndLine: 524}}},
		{ID: "fast-deep-equal@3.1.3", Name: "fast-deep-equal", Version: "3.1.3", Locations: []types.Location{{StartLine: 526, EndLine: 531}}},
		{ID: "fast-json-stable-stringify@2.1.0", Name: "fast-json-stable-stringify", Version: "2.1.0", Locations: []types.Location{{StartLine: 533, EndLine: 538}}},
		{ID: "fill-range@7.0.1", Name: "fill-range", Version: "7.0.1", Locations: []types.Location{{StartLine: 540, EndLine: 547}}},
		{ID: "find-up@5.0.0", Name: "find-up", Version: "5.0.0", Locations: []types.Location{{StartLine: 549, EndLine: 557}}},
		{ID: "find-up@3.0.0", Name: "find-up", Version: "3.0.0", Locations: []types.Location{{StartLine: 559, EndLine: 566}}},
		{ID: "flat@4.1.0", Name: "flat", Version: "4.1.0", Locations: []types.Location{{StartLine: 568, EndLine: 577}}},
		{ID: "forever-agent@0.6.1", Name: "forever-agent", Version: "0.6.1", Locations: []types.Location{{StartLine: 579, EndLine: 584}}},
		{ID: "form-data@2.3.3", Name: "form-data", Version: "2.3.3", Locations: []types.Location{{StartLine: 586, EndLine: 595}}},
		{ID: "fs-minipass@2.1.0", Name: "fs-minipass", Version: "2.1.0", Locations: []types.Location{{StartLine: 597, EndLine: 604}}},
		{ID: "fs.realpath@1.0.0", Name: "fs.realpath", Version: "1.0.0", Locations: []types.Location{{StartLine: 606, EndLine: 611}}},
		{ID: "fsevents@2.1.3", Name: "fsevents", Version: "2.1.3", Locations: []types.Location{{StartLine: 622, EndLine: 629}}},
		{ID: "function-bind@1.1.1", Name: "function-bind", Version: "1.1.1", Locations: []types.Location{{StartLine: 631, EndLine: 636}}},
		{ID: "gauge@2.7.4", Name: "gauge", Version: "2.7.4", Locations: []types.Location{{StartLine: 638, EndLine: 652}}},
		{ID: "get-caller-file@2.0.5", Name: "get-caller-file", Version: "2.0.5", Locations: []types.Location{{StartLine: 654, EndLine: 659}}},
		{ID: "getpass@0.1.7", Name: "getpass", Version: "0.1.7", Locations: []types.Location{{StartLine: 661, EndLine: 668}}},
		{ID: "glob-parent@5.1.1", Name: "glob-parent", Version: "5.1.1", Locations: []types.Location{{StartLine: 670, EndLine: 677}}},
		{ID: "glob@7.1.6", Name: "glob", Version: "7.1.6", Locations: []types.Location{{StartLine: 679, EndLine: 691}}},
		{ID: "graceful-fs@4.2.4", Name: "graceful-fs", Version: "4.2.4", Locations: []types.Location{{StartLine: 693, EndLine: 698}}},
		{ID: "growl@1.10.5", Name: "growl", Version: "1.10.5", Locations: []types.Location{{StartLine: 700, EndLine: 705}}},
		{ID: "har-schema@2.0.0", Name: "har-schema", Version: "2.0.0", Locations: []types.Location{{StartLine: 707, EndLine: 712}}},
		{ID: "har-validator@5.1.5", Name: "har-validator", Version: "5.1.5", Locations: []types.Location{{StartLine: 714, EndLine: 722}}},
		{ID: "has-flag@4.0.0", Name: "has-flag", Version: "4.0.0", Locations: []types.Location{{StartLine: 724, EndLine: 729}}},
		{ID: "has-symbols@1.0.1", Name: "has-symbols", Version: "1.0.1", Locations: []types.Location{{StartLine: 731, EndLine: 736}}},
		{ID: "has-unicode@2.0.1", Name: "has-unicode", Version: "2.0.1", Locations: []types.Location{{StartLine: 738, EndLine: 743}}},
		{ID: "has@1.0.3", Name: "has", Version: "1.0.3", Locations: []types.Location{{StartLine: 745, EndLine: 752}}},
		{ID: "he@1.2.0", Name: "he", Version: "1.2.0", Locations: []types.Location{{StartLine: 754, EndLine: 761}}},
		{ID: "http-signature@1.2.0", Name: "http-signature", Version: "1.2.0", Locations: []types.Location{{StartLine: 763, EndLine: 772}}},
		{ID: "inflight@1.0.6", Name: "inflight", Version: "1.0.6", Locations: []types.Location{{StartLine: 774, EndLine: 782}}},
		{ID: "inherits@2.0.4", Name: "inherits", Version: "2.0.4", Locations: []types.Location{{StartLine: 784, EndLine: 789}}},
		{ID: "is-arguments@1.0.4", Name: "is-arguments", Version: "1.0.4", Locations: []types.Location{{StartLine: 791, EndLine: 796}}},
		{ID: "is-binary-path@2.1.0", Name: "is-binary-path", Version: "2.1.0", Locations: []types.Location{{StartLine: 798, EndLine: 805}}},
		{ID: "is-buffer@2.0.4", Name: "is-buffer", Version: "2.0.4", Locations: []types.Location{{StartLine: 807, EndLine: 812}}},
		{ID: "is-callable@1.2.0", Name: "is-callable", Version: "1.2.0", Locations: []types.Location{{StartLine: 814, EndLine: 819}}},
		{ID: "is-date-object@1.0.2", Name: "is-date-object", Version: "1.0.2", Locations: []types.Location{{StartLine: 821, EndLine: 826}}},
		{ID: "is-extglob@2.1.1", Name: "is-extglob", Version: "2.1.1", Locations: []types.Location{{StartLine: 828, EndLine: 833}}},
		{ID: "is-fullwidth-code-point@1.0.0", Name: "is-fullwidth-code-point", Version: "1.0.0", Locations: []types.Location{{StartLine: 835, EndLine: 842}}},
		{ID: "is-fullwidth-code-point@2.0.0", Name: "is-fullwidth-code-point", Version: "2.0.0", Locations: []types.Location{{StartLine: 844, EndLine: 849}}},
		{ID: "is-glob@4.0.1", Name: "is-glob", Version: "4.0.1", Locations: []types.Location{{StartLine: 851, EndLine: 858}}},
		{ID: "is-map@2.0.1", Name: "is-map", Version: "2.0.1", Locations: []types.Location{{StartLine: 860, EndLine: 865}}},
		{ID: "is-number@7.0.0", Name: "is-number", Version: "7.0.0", Locations: []types.Location{{StartLine: 867, EndLine: 872}}},
		{ID: "is-plain-obj@1.1.0", Name: "is-plain-obj", Version: "1.1.0", Locations: []types.Location{{StartLine: 874, EndLine: 879}}},
		{ID: "is-regex@1.1.1", Name: "is-regex", Version: "1.1.1", Locations: []types.Location{{StartLine: 881, EndLine: 888}}},
		{ID: "is-set@2.0.1", Name: "is-set", Version: "2.0.1", Locations: []types.Location{{StartLine: 890, EndLine: 895}}},
		{ID: "is-string@1.0.5", Name: "is-string", Version: "1.0.5", Locations: []types.Location{{StartLine: 897, EndLine: 902}}},
		{ID: "is-symbol@1.0.3", Name: "is-symbol", Version: "1.0.3", Locations: []types.Location{{StartLine: 904, EndLine: 911}}},
		{ID: "is-typedarray@1.0.0", Name: "is-typedarray", Version: "1.0.0", Locations: []types.Location{{StartLine: 913, EndLine: 918}}},
		{ID: "isarray@2.0.5", Name: "isarray", Version: "2.0.5", Locations: []types.Location{{StartLine: 920, EndLine: 925}}},
		{ID: "isarray@1.0.0", Name: "isarray", Version: "1.0.0", Locations: []types.Location{{StartLine: 927, EndLine: 932}}},
		{ID: "isexe@2.0.0", Name: "isexe", Version: "2.0.0", Locations: []types.Location{{StartLine: 934, EndLine: 939}}},
		{ID: "isstream@0.1.2", Name: "isstream", Version: "0.1.2", Locations: []types.Location{{StartLine: 941, EndLine: 946}}},
		{ID: "iterate-iterator@1.0.1", Name: "iterate-iterator", Version: "1.0.1", Locations: []types.Location{{StartLine: 948, EndLine: 953}}},
		{ID: "iterate-value@1.0.2", Name: "iterate-value", Version: "1.0.2", Locations: []types.Location{{StartLine: 955, EndLine: 963}}},
		{ID: "jquery@3.5.1", Name: "jquery", Version: "3.5.1", Locations: []types.Location{{StartLine: 965, EndLine: 970}}},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Locations: []types.Location{{StartLine: 972, EndLine: 977}}},
		{ID: "js-yaml@3.14.0", Name: "js-yaml", Version: "3.14.0", Locations: []types.Location{{StartLine: 979, EndLine: 989}}},
		{ID: "jsbn@0.1.1", Name: "jsbn", Version: "0.1.1", Locations: []types.Location{{StartLine: 991, EndLine: 996}}},
		{ID: "json-schema-traverse@0.4.1", Name: "json-schema-traverse", Version: "0.4.1", Locations: []types.Location{{StartLine: 998, EndLine: 1003}}},
		{ID: "json-schema@0.2.3", Name: "json-schema", Version: "0.2.3", Locations: []types.Location{{StartLine: 1005, EndLine: 1010}}},
		{ID: "json-stringify-safe@5.0.1", Name: "json-stringify-safe", Version: "5.0.1", Locations: []types.Location{{StartLine: 1012, EndLine: 1017}}},
		{ID: "jsprim@1.4.1", Name: "jsprim", Version: "1.4.1", Locations: []types.Location{{StartLine: 1019, EndLine: 1029}}},
		{ID: "locate-path@3.0.0", Name: "locate-path", Version: "3.0.0", Locations: []types.Location{{StartLine: 1031, EndLine: 1039}}},
		{ID: "locate-path@6.0.0", Name: "locate-path", Version: "6.0.0", Locations: []types.Location{{StartLine: 1041, EndLine: 1048}}},
		{ID: "log-symbols@4.0.0", Name: "log-symbols", Version: "4.0.0", Locations: []types.Location{{StartLine: 1050, EndLine: 1057}}},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Locations: []types.Location{{StartLine: 1059, EndLine: 1068}}},
		{ID: "mime-db@1.44.0", Name: "mime-db", Version: "1.44.0", Locations: []types.Location{{StartLine: 1070, EndLine: 1075}}},
		{ID: "mime-types@2.1.27", Name: "mime-types", Version: "2.1.27", Locations: []types.Location{{StartLine: 1077, EndLine: 1084}}},
		{ID: "minimatch@3.0.4", Name: "minimatch", Version: "3.0.4", Locations: []types.Location{{StartLine: 1086, EndLine: 1093}}},
		{ID: "minipass@3.1.3", Name: "minipass", Version: "3.1.3", Locations: []types.Location{{StartLine: 1095, EndLine: 1102}}},
		{ID: "minizlib@2.1.2", Name: "minizlib", Version: "2.1.2", Locations: []types.Location{{StartLine: 1104, EndLine: 1112}}},
		{ID: "mkdirp@1.0.4", Name: "mkdirp", Version: "1.0.4", Locations: []types.Location{{StartLine: 1114, EndLine: 1121}}},
		{ID: "mocha@8.1.3", Name: "mocha", Version: "8.1.3", Locations: []types.Location{{StartLine: 1123, EndLine: 1157}}},
		{ID: "ms@2.1.2", Name: "ms", Version: "2.1.2", Locations: []types.Location{{StartLine: 1159, EndLine: 1164}}},
		{ID: "node-gyp@7.1.0", Name: "node-gyp", Version: "7.1.0", Locations: []types.Location{{StartLine: 1166, EndLine: 1184}}},
		{ID: "nopt@4.0.3", Name: "nopt", Version: "4.0.3", Locations: []types.Location{{StartLine: 1186, EndLine: 1196}}},
		{ID: "normalize-path@3.0.0", Name: "normalize-path", Version: "3.0.0", Locations: []types.Location{{StartLine: 1198, EndLine: 1203}}},
		{ID: "npmlog@4.1.2", Name: "npmlog", Version: "4.1.2", Locations: []types.Location{{StartLine: 1205, EndLine: 1215}}},
		{ID: "number-is-nan@1.0.1", Name: "number-is-nan", Version: "1.0.1", Locations: []types.Location{{StartLine: 1217, EndLine: 1222}}},
		{ID: "oauth-sign@0.9.0", Name: "oauth-sign", Version: "0.9.0", Locations: []types.Location{{StartLine: 1224, EndLine: 1229}}},
		{ID: "object-assign@4.1.1", Name: "object-assign", Version: "4.1.1", Locations: []types.Location{{StartLine: 1231, EndLine: 1236}}},
		{ID: "object-inspect@1.8.0", Name: "object-inspect", Version: "1.8.0", Locations: []types.Location{{StartLine: 1238, EndLine: 1243}}},
		{ID: "object-keys@1.1.1", Name: "object-keys", Version: "1.1.1", Locations: []types.Location{{StartLine: 1245, EndLine: 1250}}},
		{ID: "object.assign@4.1.0", Name: "object.assign", Version: "4.1.0", Locations: []types.Location{{StartLine: 1252, EndLine: 1262}}},
		{ID: "once@1.4.0", Name: "once", Version: "1.4.0", Locations: []types.Location{{StartLine: 1264, EndLine: 1271}}},
		{ID: "os-homedir@1.0.2", Name: "os-homedir", Version: "1.0.2", Locations: []types.Location{{StartLine: 1273, EndLine: 1278}}},
		{ID: "os-tmpdir@1.0.2", Name: "os-tmpdir", Version: "1.0.2", Locations: []types.Location{{StartLine: 1280, EndLine: 1285}}},
		{ID: "osenv@0.1.5", Name: "osenv", Version: "0.1.5", Locations: []types.Location{{StartLine: 1287, EndLine: 1295}}},
		{ID: "p-limit@2.3.0", Name: "p-limit", Version: "2.3.0", Locations: []types.Location{{StartLine: 1297, EndLine: 1304}}},
		{ID: "p-limit@3.0.2", Name: "p-limit", Version: "3.0.2", Locations: []types.Location{{StartLine: 1306, EndLine: 1313}}},
		{ID: "p-locate@3.0.0", Name: "p-locate", Version: "3.0.0", Locations: []types.Location{{StartLine: 1315, EndLine: 1322}}},
		{ID: "p-locate@5.0.0", Name: "p-locate", Version: "5.0.0", Locations: []types.Location{{StartLine: 1324, EndLine: 1331}}},
		{ID: "p-try@2.2.0", Name: "p-try", Version: "2.2.0", Locations: []types.Location{{StartLine: 1333, EndLine: 1338}}},
		{ID: "path-exists@3.0.0", Name: "path-exists", Version: "3.0.0", Locations: []types.Location{{StartLine: 1340, EndLine: 1345}}},
		{ID: "path-exists@4.0.0", Name: "path-exists", Version: "4.0.0", Locations: []types.Location{{StartLine: 1347, EndLine: 1352}}},
		{ID: "path-is-absolute@1.0.1", Name: "path-is-absolute", Version: "1.0.1", Locations: []types.Location{{StartLine: 1354, EndLine: 1359}}},
		{ID: "performance-now@2.1.0", Name: "performance-now", Version: "2.1.0", Locations: []types.Location{{StartLine: 1361, EndLine: 1366}}},
		{ID: "picomatch@2.2.2", Name: "picomatch", Version: "2.2.2", Locations: []types.Location{{StartLine: 1368, EndLine: 1373}}},
		{ID: "process-nextick-args@2.0.1", Name: "process-nextick-args", Version: "2.0.1", Locations: []types.Location{{StartLine: 1375, EndLine: 1380}}},
		{ID: "promise.allsettled@1.0.2", Name: "promise.allsettled", Version: "1.0.2", Locations: []types.Location{{StartLine: 1382, EndLine: 1393}}},
		{ID: "promise@8.1.0", Name: "promise", Version: "8.1.0", Locations: []types.Location{{StartLine: 1395, EndLine: 1402}}},
		{ID: "prop-types@15.7.2", Name: "prop-types", Version: "15.7.2", Locations: []types.Location{{StartLine: 1404, EndLine: 1413}}},
		{ID: "psl@1.8.0", Name: "psl", Version: "1.8.0", Locations: []types.Location{{StartLine: 1415, EndLine: 1420}}},
		{ID: "punycode@2.1.1", Name: "punycode", Version: "2.1.1", Locations: []types.Location{{StartLine: 1422, EndLine: 1427}}},
		{ID: "qs@6.5.2", Name: "qs", Version: "6.5.2", Locations: []types.Location{{StartLine: 1429, EndLine: 1434}}},
		{ID: "randombytes@2.1.0", Name: "randombytes", Version: "2.1.0", Locations: []types.Location{{StartLine: 1436, EndLine: 1443}}},
		{ID: "react-is@16.13.1", Name: "react-is", Version: "16.13.1", Locations: []types.Location{{StartLine: 1445, EndLine: 1450}}},
		{ID: "react@16.13.1", Name: "react", Version: "16.13.1", Locations: []types.Location{{StartLine: 1452, EndLine: 1461}}},
		{ID: "readable-stream@2.3.7", Name: "readable-stream", Version: "2.3.7", Locations: []types.Location{{StartLine: 1463, EndLine: 1476}}},
		{ID: "readdirp@3.4.0", Name: "readdirp", Version: "3.4.0", Locations: []types.Location{{StartLine: 1478, EndLine: 1485}}},
		{ID: "redux@4.0.5", Name: "redux", Version: "4.0.5", Locations: []types.Location{{StartLine: 1487, EndLine: 1495}}},
		{ID: "request@2.88.2", Name: "request", Version: "2.88.2", Locations: []types.Location{{StartLine: 1497, EndLine: 1523}}},
		{ID: "require-directory@2.1.1", Name: "require-directory", Version: "2.1.1", Locations: []types.Location{{StartLine: 1525, EndLine: 1530}}},
		{ID: "require-main-filename@2.0.0", Name: "require-main-filename", Version: "2.0.0", Locations: []types.Location{{StartLine: 1532, EndLine: 1537}}},
		{ID: "rimraf@2.7.1", Name: "rimraf", Version: "2.7.1", Locations: []types.Location{{StartLine: 1539, EndLine: 1548}}},
		{ID: "safe-buffer@5.2.1", Name: "safe-buffer", Version: "5.2.1", Locations: []types.Location{{StartLine: 1550, EndLine: 1555}}},
		{ID: "safe-buffer@5.1.2", Name: "safe-buffer", Version: "5.1.2", Locations: []types.Location{{StartLine: 1557, EndLine: 1562}}},
		{ID: "safer-buffer@2.1.2", Name: "safer-buffer", Version: "2.1.2", Locations: []types.Location{{StartLine: 1564, EndLine: 1569}}},
		{ID: "semver@7.3.2", Name: "semver", Version: "7.3.2", Locations: []types.Location{{StartLine: 1571, EndLine: 1578}}},
		{ID: "serialize-javascript@4.0.0", Name: "serialize-javascript", Version: "4.0.0", Locations: []types.Location{{StartLine: 1580, EndLine: 1587}}},
		{ID: "set-blocking@2.0.0", Name: "set-blocking", Version: "2.0.0", Locations: []types.Location{{StartLine: 1589, EndLine: 1594}}},
		{ID: "signal-exit@3.0.3", Name: "signal-exit", Version: "3.0.3", Locations: []types.Location{{StartLine: 1596, EndLine: 1601}}},
		{ID: "sprintf-js@1.0.3", Name: "sprintf-js", Version: "1.0.3", Locations: []types.Location{{StartLine: 1603, EndLine: 1608}}},
		{ID: "sshpk@1.16.1", Name: "sshpk", Version: "1.16.1", Locations: []types.Location{{StartLine: 1610, EndLine: 1629}}},
		{ID: "string-width@1.0.2", Name: "string-width", Version: "1.0.2", Locations: []types.Location{{StartLine: 1631, EndLine: 1640}}},
		{ID: "string-width@2.1.1", Name: "string-width", Version: "2.1.1", Locations: []types.Location{{StartLine: 1642, EndLine: 1650}}},
		{ID: "string-width@3.1.0", Name: "string-width", Version: "3.1.0", Locations: []types.Location{{StartLine: 1652, EndLine: 1661}}},
		{ID: "string.prototype.trimend@1.0.1", Name: "string.prototype.trimend", Version: "1.0.1", Locations: []types.Location{{StartLine: 1663, EndLine: 1671}}},
		{ID: "string.prototype.trimstart@1.0.1", Name: "string.prototype.trimstart", Version: "1.0.1", Locations: []types.Location{{StartLine: 1673, EndLine: 1681}}},
		{ID: "string_decoder@1.1.1", Name: "string_decoder", Version: "1.1.1", Locations: []types.Location{{StartLine: 1683, EndLine: 1690}}},
		{ID: "strip-ansi@3.0.1", Name: "strip-ansi", Version: "3.0.1", Locations: []types.Location{{StartLine: 1692, EndLine: 1699}}},
		{ID: "strip-ansi@4.0.0", Name: "strip-ansi", Version: "4.0.0", Locations: []types.Location{{StartLine: 1701, EndLine: 1708}}},
		{ID: "strip-ansi@5.2.0", Name: "strip-ansi", Version: "5.2.0", Locations: []types.Location{{StartLine: 1710, EndLine: 1717}}},
		{ID: "strip-json-comments@3.0.1", Name: "strip-json-comments", Version: "3.0.1", Locations: []types.Location{{StartLine: 1719, EndLine: 1724}}},
		{ID: "supports-color@7.1.0", Name: "supports-color", Version: "7.1.0", Locations: []types.Location{{StartLine: 1726, EndLine: 1733}}},
		{ID: "symbol-observable@1.2.0", Name: "symbol-observable", Version: "1.2.0", Locations: []types.Location{{StartLine: 1735, EndLine: 1740}}},
		{ID: "tar@6.0.5", Name: "tar", Version: "6.0.5", Locations: []types.Location{{StartLine: 1742, EndLine: 1754}}},
		{ID: "to-regex-range@5.0.1", Name: "to-regex-range", Version: "5.0.1", Locations: []types.Location{{StartLine: 1756, EndLine: 1763}}},
		{ID: "tough-cookie@2.5.0", Name: "tough-cookie", Version: "2.5.0", Locations: []types.Location{{StartLine: 1765, EndLine: 1773}}},
		{ID: "tunnel-agent@0.6.0", Name: "tunnel-agent", Version: "0.6.0", Locations: []types.Location{{StartLine: 1775, EndLine: 1782}}},
		{ID: "tweetnacl@0.14.5", Name: "tweetnacl", Version: "0.14.5", Locations: []types.Location{{StartLine: 1784, EndLine: 1789}}},
		{ID: "uri-js@4.4.0", Name: "uri-js", Version: "4.4.0", Locations: []types.Location{{StartLine: 1791, EndLine: 1798}}},
		{ID: "util-deprecate@1.0.2", Name: "util-deprecate", Version: "1.0.2", Locations: []types.Location{{StartLine: 1800, EndLine: 1805}}},
		{ID: "uuid@3.4.0", Name: "uuid", Version: "3.4.0", Locations: []types.Location{{StartLine: 1807, EndLine: 1814}}},
		{ID: "verror@1.10.0", Name: "verror", Version: "1.10.0", Locations: []types.Location{{StartLine: 1816, EndLine: 1825}}},
		{ID: "which-module@2.0.0", Name: "which-module", Version: "2.0.0", Locations: []types.Location{{StartLine: 1827, EndLine: 1832}}},
		{ID: "which@2.0.2", Name: "which", Version: "2.0.2", Locations: []types.Location{{StartLine: 1834, EndLine: 1843}}},
		{ID: "wide-align@1.1.3", Name: "wide-align", Version: "1.1.3", Locations: []types.Location{{StartLine: 1845, EndLine: 1852}}},
		{ID: "workerpool@6.0.0", Name: "workerpool", Version: "6.0.0", Locations: []types.Location{{StartLine: 1854, EndLine: 1859}}},
		{ID: "wrap-ansi@5.1.0", Name: "wrap-ansi", Version: "5.1.0", Locations: []types.Location{{StartLine: 1861, EndLine: 1870}}},
		{ID: "wrappy@1.0.2", Name: "wrappy", Version: "1.0.2", Locations: []types.Location{{StartLine: 1872, EndLine: 1877}}},
		{ID: "y18n@4.0.0", Name: "y18n", Version: "4.0.0", Locations: []types.Location{{StartLine: 1879, EndLine: 1884}}},
		{ID: "yallist@4.0.0", Name: "yallist", Version: "4.0.0", Locations: []types.Location{{StartLine: 1886, EndLine: 1891}}},
		{ID: "yargs-parser@13.1.2", Name: "yargs-parser", Version: "13.1.2", Locations: []types.Location{{StartLine: 1893, EndLine: 1901}}},
		{ID: "yargs-parser@15.0.1", Name: "yargs-parser", Version: "15.0.1", Locations: []types.Location{{StartLine: 1903, EndLine: 1911}}},
		{ID: "yargs-unparser@1.6.1", Name: "yargs-unparser", Version: "1.6.1", Locations: []types.Location{{StartLine: 1913, EndLine: 1924}}},
		{ID: "yargs@13.3.2", Name: "yargs", Version: "13.3.2", Locations: []types.Location{{StartLine: 1926, EndLine: 1942}}},
		{ID: "yargs@14.2.3", Name: "yargs", Version: "14.2.3", Locations: []types.Location{{StartLine: 1944, EndLine: 1961}}},
	}

	// ... and
	// node test_deps_generator/index.js yarn.lock
	yarnV2WithDevDeps = []types.Dependency{
		{
			ID: "promise@8.1.0",
			DependsOn: []string{
				"asap@2.0.6",
			},
		},
		{
			ID: "loose-envify@1.4.0",
			DependsOn: []string{
				"js-tokens@4.0.0",
			},
		},
		{
			ID: "react@16.13.1",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"prop-types@15.7.2",
			},
		},
		{
			ID: "prop-types@15.7.2",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"react-is@16.13.1",
			},
		},
		{
			ID: "redux@4.0.5",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"symbol-observable@1.2.0",
			},
		},
		{
			ID: "mocha@8.1.3",
			DependsOn: []string{
				"ansi-colors@4.1.1",
				"browser-stdout@1.3.1",
				"chokidar@3.4.2",
				"debug@4.1.1",
				"diff@4.0.2",
				"escape-string-regexp@4.0.0",
				"find-up@5.0.0",
				"glob@7.1.6",
				"growl@1.10.5",
				"he@1.2.0",
				"js-yaml@3.14.0",
				"log-symbols@4.0.0",
				"minimatch@3.0.4",
				"ms@2.1.2",
				"object.assign@4.1.0",
				"promise.allsettled@1.0.2",
				"serialize-javascript@4.0.0",
				"strip-json-comments@3.0.1",
				"supports-color@7.1.0",
				"which@2.0.2",
				"wide-align@1.1.3",
				"workerpool@6.0.0",
				"yargs@13.3.2",
				"yargs-parser@13.1.2",
				"yargs-unparser@1.6.1",
			},
		},
		{
			ID: "anymatch@3.1.1",
			DependsOn: []string{
				"normalize-path@3.0.0",
				"picomatch@2.2.2",
			},
		},
		{
			ID: "chokidar@3.4.2",
			DependsOn: []string{
				"anymatch@3.1.1",
				"braces@3.0.2",
				"fsevents@2.1.3",
				"glob-parent@5.1.1",
				"is-binary-path@2.1.0",
				"is-glob@4.0.1",
				"normalize-path@3.0.0",
				"readdirp@3.4.0",
			},
		},
		{
			ID: "to-regex-range@5.0.1",
			DependsOn: []string{
				"is-number@7.0.0",
			},
		},
		{
			ID: "fill-range@7.0.1",
			DependsOn: []string{
				"to-regex-range@5.0.1",
			},
		},
		{
			ID: "braces@3.0.2",
			DependsOn: []string{
				"fill-range@7.0.1",
			},
		},
		{
			ID: "node-gyp@7.1.0",
			DependsOn: []string{
				"env-paths@2.2.0",
				"glob@7.1.6",
				"graceful-fs@4.2.4",
				"nopt@4.0.3",
				"npmlog@4.1.2",
				"request@2.88.2",
				"rimraf@2.7.1",
				"semver@7.3.2",
				"tar@6.0.5",
				"which@2.0.2",
			},
		},
		{
			ID: "glob@7.1.6",
			DependsOn: []string{
				"fs.realpath@1.0.0",
				"inflight@1.0.6",
				"inherits@2.0.4",
				"minimatch@3.0.4",
				"once@1.4.0",
				"path-is-absolute@1.0.1",
			},
		},
		{
			ID: "once@1.4.0",
			DependsOn: []string{
				"wrappy@1.0.2",
			},
		},
		{
			ID: "inflight@1.0.6",
			DependsOn: []string{
				"once@1.4.0",
				"wrappy@1.0.2",
			},
		},
		{
			ID: "brace-expansion@1.1.11",
			DependsOn: []string{
				"balanced-match@1.0.0",
				"concat-map@0.0.1",
			},
		},
		{
			ID: "minimatch@3.0.4",
			DependsOn: []string{
				"brace-expansion@1.1.11",
			},
		},
		{
			ID: "nopt@4.0.3",
			DependsOn: []string{
				"abbrev@1.1.1",
				"osenv@0.1.5",
			},
		},
		{
			ID: "osenv@0.1.5",
			DependsOn: []string{
				"os-homedir@1.0.2",
				"os-tmpdir@1.0.2",
			},
		},
		{
			ID: "are-we-there-yet@1.1.5",
			DependsOn: []string{
				"delegates@1.0.0",
				"readable-stream@2.3.7",
			},
		},
		{
			ID: "readable-stream@2.3.7",
			DependsOn: []string{
				"core-util-is@1.0.2",
				"inherits@2.0.4",
				"isarray@1.0.0",
				"process-nextick-args@2.0.1",
				"safe-buffer@5.1.2",
				"string_decoder@1.1.1",
				"util-deprecate@1.0.2",
			},
		},
		{
			ID: "string_decoder@1.1.1",
			DependsOn: []string{
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "npmlog@4.1.2",
			DependsOn: []string{
				"are-we-there-yet@1.1.5",
				"console-control-strings@1.1.0",
				"gauge@2.7.4",
				"set-blocking@2.0.0",
			},
		},
		{
			ID: "gauge@2.7.4",
			DependsOn: []string{
				"aproba@1.2.0",
				"console-control-strings@1.1.0",
				"has-unicode@2.0.1",
				"object-assign@4.1.1",
				"signal-exit@3.0.3",
				"string-width@1.0.2",
				"strip-ansi@3.0.1",
				"wide-align@1.1.3",
			},
		},
		{
			ID: "string-width@1.0.2",
			DependsOn: []string{
				"code-point-at@1.1.0",
				"is-fullwidth-code-point@1.0.0",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID: "is-fullwidth-code-point@1.0.0",
			DependsOn: []string{
				"number-is-nan@1.0.1",
			},
		},
		{
			ID: "strip-ansi@3.0.1",
			DependsOn: []string{
				"ansi-regex@2.1.1",
			},
		},
		{
			ID: "string-width@2.1.1",
			DependsOn: []string{
				"is-fullwidth-code-point@2.0.0",
				"strip-ansi@4.0.0",
			},
		},
		{
			ID: "strip-ansi@4.0.0",
			DependsOn: []string{
				"ansi-regex@3.0.0",
			},
		},
		{
			ID: "wide-align@1.1.3",
			DependsOn: []string{
				"string-width@2.1.1",
			},
		},
		{
			ID: "request@2.88.2",
			DependsOn: []string{
				"aws-sign2@0.7.0",
				"aws4@1.10.1",
				"caseless@0.12.0",
				"combined-stream@1.0.8",
				"extend@3.0.2",
				"forever-agent@0.6.1",
				"form-data@2.3.3",
				"har-validator@5.1.5",
				"http-signature@1.2.0",
				"is-typedarray@1.0.0",
				"isstream@0.1.2",
				"json-stringify-safe@5.0.1",
				"mime-types@2.1.27",
				"oauth-sign@0.9.0",
				"performance-now@2.1.0",
				"qs@6.5.2",
				"safe-buffer@5.2.1",
				"tough-cookie@2.5.0",
				"tunnel-agent@0.6.0",
				"uuid@3.4.0",
			},
		},
		{
			ID: "combined-stream@1.0.8",
			DependsOn: []string{
				"delayed-stream@1.0.0",
			},
		},
		{
			ID: "form-data@2.3.3",
			DependsOn: []string{
				"asynckit@0.4.0",
				"combined-stream@1.0.8",
				"mime-types@2.1.27",
			},
		},
		{
			ID: "mime-types@2.1.27",
			DependsOn: []string{
				"mime-db@1.44.0",
			},
		},
		{
			ID: "ajv@6.12.4",
			DependsOn: []string{
				"fast-deep-equal@3.1.3",
				"fast-json-stable-stringify@2.1.0",
				"json-schema-traverse@0.4.1",
				"uri-js@4.4.0",
			},
		},
		{
			ID: "uri-js@4.4.0",
			DependsOn: []string{
				"punycode@2.1.1",
			},
		},
		{
			ID: "har-validator@5.1.5",
			DependsOn: []string{
				"ajv@6.12.4",
				"har-schema@2.0.0",
			},
		},
		{
			ID: "http-signature@1.2.0",
			DependsOn: []string{
				"assert-plus@1.0.0",
				"jsprim@1.4.1",
				"sshpk@1.16.1",
			},
		},
		{
			ID: "jsprim@1.4.1",
			DependsOn: []string{
				"assert-plus@1.0.0",
				"extsprintf@1.3.0",
				"json-schema@0.2.3",
				"verror@1.10.0",
			},
		},
		{
			ID: "verror@1.10.0",
			DependsOn: []string{
				"assert-plus@1.0.0",
				"core-util-is@1.0.2",
				"extsprintf@1.3.0",
			},
		},
		{
			ID: "asn1@0.2.4",
			DependsOn: []string{
				"safer-buffer@2.1.2",
			},
		},
		{
			ID: "sshpk@1.16.1",
			DependsOn: []string{
				"asn1@0.2.4",
				"assert-plus@1.0.0",
				"bcrypt-pbkdf@1.0.2",
				"dashdash@1.14.1",
				"ecc-jsbn@0.1.2",
				"getpass@0.1.7",
				"jsbn@0.1.1",
				"safer-buffer@2.1.2",
				"tweetnacl@0.14.5",
			},
		},
		{
			ID: "bcrypt-pbkdf@1.0.2",
			DependsOn: []string{
				"tweetnacl@0.14.5",
			},
		},
		{
			ID: "dashdash@1.14.1",
			DependsOn: []string{
				"assert-plus@1.0.0",
			},
		},
		{
			ID: "ecc-jsbn@0.1.2",
			DependsOn: []string{
				"jsbn@0.1.1",
				"safer-buffer@2.1.2",
			},
		},
		{
			ID: "getpass@0.1.7",
			DependsOn: []string{
				"assert-plus@1.0.0",
			},
		},
		{
			ID: "tough-cookie@2.5.0",
			DependsOn: []string{
				"psl@1.8.0",
				"punycode@2.1.1",
			},
		},
		{
			ID: "tunnel-agent@0.6.0",
			DependsOn: []string{
				"safe-buffer@5.2.1",
			},
		},
		{
			ID: "rimraf@2.7.1",
			DependsOn: []string{
				"glob@7.1.6",
			},
		},
		{
			ID: "tar@6.0.5",
			DependsOn: []string{
				"chownr@2.0.0",
				"fs-minipass@2.1.0",
				"minipass@3.1.3",
				"minizlib@2.1.2",
				"mkdirp@1.0.4",
				"yallist@4.0.0",
			},
		},
		{
			ID: "minipass@3.1.3",
			DependsOn: []string{
				"yallist@4.0.0",
			},
		},
		{
			ID: "fs-minipass@2.1.0",
			DependsOn: []string{
				"minipass@3.1.3",
			},
		},
		{
			ID: "minizlib@2.1.2",
			DependsOn: []string{
				"minipass@3.1.3",
				"yallist@4.0.0",
			},
		},
		{
			ID: "which@2.0.2",
			DependsOn: []string{
				"isexe@2.0.0",
			},
		},
		{
			ID: "fsevents@2.1.3",
			DependsOn: []string{
				"node-gyp@7.1.0",
			},
		},
		{
			ID: "is-glob@4.0.1",
			DependsOn: []string{
				"is-extglob@2.1.1",
			},
		},
		{
			ID: "glob-parent@5.1.1",
			DependsOn: []string{
				"is-glob@4.0.1",
			},
		},
		{
			ID: "is-binary-path@2.1.0",
			DependsOn: []string{
				"binary-extensions@2.1.0",
			},
		},
		{
			ID: "readdirp@3.4.0",
			DependsOn: []string{
				"picomatch@2.2.2",
			},
		},
		{
			ID: "debug@4.1.1",
			DependsOn: []string{
				"ms@2.1.2",
			},
		},
		{
			ID: "p-limit@3.0.2",
			DependsOn: []string{
				"p-try@2.2.0",
			},
		},
		{
			ID: "p-locate@5.0.0",
			DependsOn: []string{
				"p-limit@3.0.2",
			},
		},
		{
			ID: "locate-path@6.0.0",
			DependsOn: []string{
				"p-locate@5.0.0",
			},
		},
		{
			ID: "find-up@5.0.0",
			DependsOn: []string{
				"locate-path@6.0.0",
				"path-exists@4.0.0",
			},
		},
		{
			ID: "argparse@1.0.10",
			DependsOn: []string{
				"sprintf-js@1.0.3",
			},
		},
		{
			ID: "js-yaml@3.14.0",
			DependsOn: []string{
				"argparse@1.0.10",
				"esprima@4.0.1",
			},
		},
		{
			ID: "ansi-styles@4.2.1",
			DependsOn: []string{
				"@types/color-name@1.1.1",
				"color-convert@2.0.1",
			},
		},
		{
			ID: "color-convert@2.0.1",
			DependsOn: []string{
				"color-name@1.1.4",
			},
		},
		{
			ID: "chalk@4.1.0",
			DependsOn: []string{
				"ansi-styles@4.2.1",
				"supports-color@7.1.0",
			},
		},
		{
			ID: "supports-color@7.1.0",
			DependsOn: []string{
				"has-flag@4.0.0",
			},
		},
		{
			ID: "log-symbols@4.0.0",
			DependsOn: []string{
				"chalk@4.1.0",
			},
		},
		{
			ID: "define-properties@1.1.3",
			DependsOn: []string{
				"object-keys@1.1.1",
			},
		},
		{
			ID: "object.assign@4.1.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"function-bind@1.1.1",
				"has-symbols@1.0.1",
				"object-keys@1.1.1",
			},
		},
		{
			ID: "array.prototype.map@1.0.2",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.17.6",
				"es-array-method-boxes-properly@1.0.0",
				"is-string@1.0.5",
			},
		},
		{
			ID: "es-to-primitive@1.2.1",
			DependsOn: []string{
				"is-callable@1.2.0",
				"is-date-object@1.0.2",
				"is-symbol@1.0.3",
			},
		},
		{
			ID: "is-symbol@1.0.3",
			DependsOn: []string{
				"has-symbols@1.0.1",
			},
		},
		{
			ID: "es-abstract@1.17.6",
			DependsOn: []string{
				"es-to-primitive@1.2.1",
				"function-bind@1.1.1",
				"has@1.0.3",
				"has-symbols@1.0.1",
				"is-callable@1.2.0",
				"is-regex@1.1.1",
				"object-inspect@1.8.0",
				"object-keys@1.1.1",
				"object.assign@4.1.0",
				"string.prototype.trimend@1.0.1",
				"string.prototype.trimstart@1.0.1",
			},
		},
		{
			ID: "has@1.0.3",
			DependsOn: []string{
				"function-bind@1.1.1",
			},
		},
		{
			ID: "is-regex@1.1.1",
			DependsOn: []string{
				"has-symbols@1.0.1",
			},
		},
		{
			ID: "string.prototype.trimend@1.0.1",
			DependsOn: []string{
				"es-abstract@1.17.6",
				"define-properties@1.1.3",
			},
		},
		{
			ID: "string.prototype.trimstart@1.0.1",
			DependsOn: []string{
				"es-abstract@1.17.6",
				"define-properties@1.1.3",
			},
		},
		{
			ID: "promise.allsettled@1.0.2",
			DependsOn: []string{
				"array.prototype.map@1.0.2",
				"define-properties@1.1.3",
				"es-abstract@1.17.6",
				"function-bind@1.1.1",
				"iterate-value@1.0.2",
			},
		},
		{
			ID: "es-get-iterator@1.1.0",
			DependsOn: []string{
				"es-abstract@1.17.6",
				"has-symbols@1.0.1",
				"is-arguments@1.0.4",
				"is-map@2.0.1",
				"is-set@2.0.1",
				"is-string@1.0.5",
				"isarray@2.0.5",
			},
		},
		{
			ID: "iterate-value@1.0.2",
			DependsOn: []string{
				"es-get-iterator@1.1.0",
				"iterate-iterator@1.0.1",
			},
		},
		{
			ID: "randombytes@2.1.0",
			DependsOn: []string{
				"safe-buffer@5.2.1",
			},
		},
		{
			ID: "serialize-javascript@4.0.0",
			DependsOn: []string{
				"randombytes@2.1.0",
			},
		},
		{
			ID: "string-width@3.1.0",
			DependsOn: []string{
				"emoji-regex@7.0.3",
				"is-fullwidth-code-point@2.0.0",
				"strip-ansi@5.2.0",
			},
		},
		{
			ID: "strip-ansi@5.2.0",
			DependsOn: []string{
				"ansi-regex@4.1.0",
			},
		},
		{
			ID: "cliui@5.0.0",
			DependsOn: []string{
				"string-width@3.1.0",
				"strip-ansi@5.2.0",
				"wrap-ansi@5.1.0",
			},
		},
		{
			ID: "color-convert@1.9.3",
			DependsOn: []string{
				"color-name@1.1.3",
			},
		},
		{
			ID: "ansi-styles@3.2.1",
			DependsOn: []string{
				"color-convert@1.9.3",
			},
		},
		{
			ID: "wrap-ansi@5.1.0",
			DependsOn: []string{
				"ansi-styles@3.2.1",
				"string-width@3.1.0",
				"strip-ansi@5.2.0",
			},
		},
		{
			ID: "yargs@13.3.2",
			DependsOn: []string{
				"cliui@5.0.0",
				"find-up@3.0.0",
				"get-caller-file@2.0.5",
				"require-directory@2.1.1",
				"require-main-filename@2.0.0",
				"set-blocking@2.0.0",
				"string-width@3.1.0",
				"which-module@2.0.0",
				"y18n@4.0.0",
				"yargs-parser@13.1.2",
			},
		},
		{
			ID: "p-limit@2.3.0",
			DependsOn: []string{
				"p-try@2.2.0",
			},
		},
		{
			ID: "p-locate@3.0.0",
			DependsOn: []string{
				"p-limit@2.3.0",
			},
		},
		{
			ID: "locate-path@3.0.0",
			DependsOn: []string{
				"p-locate@3.0.0",
				"path-exists@3.0.0",
			},
		},
		{
			ID: "find-up@3.0.0",
			DependsOn: []string{
				"locate-path@3.0.0",
			},
		},
		{
			ID: "yargs-parser@13.1.2",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
			},
		},
		{
			ID: "yargs-unparser@1.6.1",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
				"flat@4.1.0",
				"is-plain-obj@1.1.0",
				"yargs@14.2.3",
			},
		},
		{
			ID: "flat@4.1.0",
			DependsOn: []string{
				"is-buffer@2.0.4",
			},
		},
		{
			ID: "yargs@14.2.3",
			DependsOn: []string{
				"cliui@5.0.0",
				"decamelize@1.2.0",
				"find-up@3.0.0",
				"get-caller-file@2.0.5",
				"require-directory@2.1.1",
				"require-main-filename@2.0.0",
				"set-blocking@2.0.0",
				"string-width@3.1.0",
				"which-module@2.0.0",
				"y18n@4.0.0",
				"yargs-parser@15.0.1",
			},
		},
		{
			ID: "yargs-parser@15.0.1",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
			},
		},
	}

	// ... and
	// yarn add lodash request chalk commander express async axios vue
	// yarn info --recursive --dependents --json | jq -r .value | grep -v workspace | awk -F'[@:]' '{printf("{\""$1"\", \""$3"\", \"\"},\n")}'
	// to get deps with locations from lock file use following commands:
	// awk '/^\S+@[~^*]?(>= )?[0-9.]*/,/^$/{if($0=="") {print "--"prev} else { if(substr($0,1,2)!="  ") {print NR":"$0} else {print $0}} prev=NR}; END{print "--"prev}' | awk 'BEGIN {s=""}; {(substr($0,1,2)=="--") ? (s=s$0"\n") : (s=s$0)}; END { print s}' | sed -E 's/@([0-9~><*\^]|npm).*version:? "?/:/' | sed 's/  /:/' | sed 's/"//g'| awk 'match($0, /[[:digit:]]+$/) {print substr($0, RSTART, RLENGTH)":"$0 }' |  awk -F":" '{print "{ID: \""$3"@"$4"\", Name: \""$3"\", Version: \""$4"\", Locations: []types.Location{{StartLine: "$2", EndLine: "$1"}}},"}'
	// and remove 'code@workspace' and 'fsevents@patch' dependencies
	yarnV2Many = []types.Library{
		{ID: "@types/color-name@1.1.1", Name: "@types/color-name", Version: "1.1.1", Locations: []types.Location{{StartLine: 8, EndLine: 13}}},
		{ID: "abbrev@1.1.1", Name: "abbrev", Version: "1.1.1", Locations: []types.Location{{StartLine: 15, EndLine: 20}}},
		{ID: "accepts@1.3.7", Name: "accepts", Version: "1.3.7", Locations: []types.Location{{StartLine: 22, EndLine: 30}}},
		{ID: "ajv@6.12.4", Name: "ajv", Version: "6.12.4", Locations: []types.Location{{StartLine: 32, EndLine: 42}}},
		{ID: "ansi-colors@4.1.1", Name: "ansi-colors", Version: "4.1.1", Locations: []types.Location{{StartLine: 44, EndLine: 49}}},
		{ID: "ansi-regex@2.1.1", Name: "ansi-regex", Version: "2.1.1", Locations: []types.Location{{StartLine: 51, EndLine: 56}}},
		{ID: "ansi-regex@3.0.0", Name: "ansi-regex", Version: "3.0.0", Locations: []types.Location{{StartLine: 58, EndLine: 63}}},
		{ID: "ansi-regex@4.1.0", Name: "ansi-regex", Version: "4.1.0", Locations: []types.Location{{StartLine: 65, EndLine: 70}}},
		{ID: "ansi-styles@3.2.1", Name: "ansi-styles", Version: "3.2.1", Locations: []types.Location{{StartLine: 72, EndLine: 79}}},
		{ID: "ansi-styles@4.2.1", Name: "ansi-styles", Version: "4.2.1", Locations: []types.Location{{StartLine: 81, EndLine: 89}}},
		{ID: "anymatch@3.1.1", Name: "anymatch", Version: "3.1.1", Locations: []types.Location{{StartLine: 91, EndLine: 99}}},
		{ID: "aproba@1.2.0", Name: "aproba", Version: "1.2.0", Locations: []types.Location{{StartLine: 101, EndLine: 106}}},
		{ID: "are-we-there-yet@1.1.5", Name: "are-we-there-yet", Version: "1.1.5", Locations: []types.Location{{StartLine: 108, EndLine: 116}}},
		{ID: "argparse@1.0.10", Name: "argparse", Version: "1.0.10", Locations: []types.Location{{StartLine: 118, EndLine: 125}}},
		{ID: "array-flatten@1.1.1", Name: "array-flatten", Version: "1.1.1", Locations: []types.Location{{StartLine: 127, EndLine: 132}}},
		{ID: "array.prototype.map@1.0.2", Name: "array.prototype.map", Version: "1.0.2", Locations: []types.Location{{StartLine: 134, EndLine: 144}}},
		{ID: "asap@2.0.6", Name: "asap", Version: "2.0.6", Locations: []types.Location{{StartLine: 146, EndLine: 151}}},
		{ID: "asn1@0.2.4", Name: "asn1", Version: "0.2.4", Locations: []types.Location{{StartLine: 153, EndLine: 160}}},
		{ID: "assert-plus@1.0.0", Name: "assert-plus", Version: "1.0.0", Locations: []types.Location{{StartLine: 162, EndLine: 167}}},
		{ID: "async@3.2.0", Name: "async", Version: "3.2.0", Locations: []types.Location{{StartLine: 169, EndLine: 174}}},
		{ID: "asynckit@0.4.0", Name: "asynckit", Version: "0.4.0", Locations: []types.Location{{StartLine: 176, EndLine: 181}}},
		{ID: "aws-sign2@0.7.0", Name: "aws-sign2", Version: "0.7.0", Locations: []types.Location{{StartLine: 183, EndLine: 188}}},
		{ID: "aws4@1.10.1", Name: "aws4", Version: "1.10.1", Locations: []types.Location{{StartLine: 190, EndLine: 195}}},
		{ID: "axios@0.20.0", Name: "axios", Version: "0.20.0", Locations: []types.Location{{StartLine: 197, EndLine: 204}}},
		{ID: "balanced-match@1.0.0", Name: "balanced-match", Version: "1.0.0", Locations: []types.Location{{StartLine: 206, EndLine: 211}}},
		{ID: "bcrypt-pbkdf@1.0.2", Name: "bcrypt-pbkdf", Version: "1.0.2", Locations: []types.Location{{StartLine: 213, EndLine: 220}}},
		{ID: "binary-extensions@2.1.0", Name: "binary-extensions", Version: "2.1.0", Locations: []types.Location{{StartLine: 222, EndLine: 227}}},
		{ID: "body-parser@1.19.0", Name: "body-parser", Version: "1.19.0", Locations: []types.Location{{StartLine: 229, EndLine: 245}}},
		{ID: "brace-expansion@1.1.11", Name: "brace-expansion", Version: "1.1.11", Locations: []types.Location{{StartLine: 247, EndLine: 255}}},
		{ID: "braces@3.0.2", Name: "braces", Version: "3.0.2", Locations: []types.Location{{StartLine: 257, EndLine: 264}}},
		{ID: "browser-stdout@1.3.1", Name: "browser-stdout", Version: "1.3.1", Locations: []types.Location{{StartLine: 266, EndLine: 271}}},
		{ID: "bytes@3.1.0", Name: "bytes", Version: "3.1.0", Locations: []types.Location{{StartLine: 273, EndLine: 278}}},
		{ID: "camelcase@5.3.1", Name: "camelcase", Version: "5.3.1", Locations: []types.Location{{StartLine: 280, EndLine: 285}}},
		{ID: "caseless@0.12.0", Name: "caseless", Version: "0.12.0", Locations: []types.Location{{StartLine: 287, EndLine: 292}}},
		{ID: "chalk@4.1.0", Name: "chalk", Version: "4.1.0", Locations: []types.Location{{StartLine: 294, EndLine: 302}}},
		{ID: "chokidar@3.4.2", Name: "chokidar", Version: "3.4.2", Locations: []types.Location{{StartLine: 304, EndLine: 321}}},
		{ID: "chownr@2.0.0", Name: "chownr", Version: "2.0.0", Locations: []types.Location{{StartLine: 323, EndLine: 328}}},
		{ID: "cliui@5.0.0", Name: "cliui", Version: "5.0.0", Locations: []types.Location{{StartLine: 330, EndLine: 339}}},
		{ID: "code-point-at@1.1.0", Name: "code-point-at", Version: "1.1.0", Locations: []types.Location{{StartLine: 341, EndLine: 346}}},
		{ID: "color-convert@1.9.3", Name: "color-convert", Version: "1.9.3", Locations: []types.Location{{StartLine: 368, EndLine: 375}}},
		{ID: "color-convert@2.0.1", Name: "color-convert", Version: "2.0.1", Locations: []types.Location{{StartLine: 377, EndLine: 384}}},
		{ID: "color-name@1.1.3", Name: "color-name", Version: "1.1.3", Locations: []types.Location{{StartLine: 386, EndLine: 391}}},
		{ID: "color-name@1.1.4", Name: "color-name", Version: "1.1.4", Locations: []types.Location{{StartLine: 393, EndLine: 398}}},
		{ID: "combined-stream@1.0.8", Name: "combined-stream", Version: "1.0.8", Locations: []types.Location{{StartLine: 400, EndLine: 407}}},
		{ID: "commander@6.1.0", Name: "commander", Version: "6.1.0", Locations: []types.Location{{StartLine: 409, EndLine: 414}}},
		{ID: "concat-map@0.0.1", Name: "concat-map", Version: "0.0.1", Locations: []types.Location{{StartLine: 416, EndLine: 421}}},
		{ID: "console-control-strings@1.1.0", Name: "console-control-strings", Version: "1.1.0", Locations: []types.Location{{StartLine: 423, EndLine: 428}}},
		{ID: "content-disposition@0.5.3", Name: "content-disposition", Version: "0.5.3", Locations: []types.Location{{StartLine: 430, EndLine: 437}}},
		{ID: "content-type@1.0.4", Name: "content-type", Version: "1.0.4", Locations: []types.Location{{StartLine: 439, EndLine: 444}}},
		{ID: "cookie-signature@1.0.6", Name: "cookie-signature", Version: "1.0.6", Locations: []types.Location{{StartLine: 446, EndLine: 451}}},
		{ID: "cookie@0.4.0", Name: "cookie", Version: "0.4.0", Locations: []types.Location{{StartLine: 453, EndLine: 458}}},
		{ID: "core-util-is@1.0.2", Name: "core-util-is", Version: "1.0.2", Locations: []types.Location{{StartLine: 460, EndLine: 465}}},
		{ID: "dashdash@1.14.1", Name: "dashdash", Version: "1.14.1", Locations: []types.Location{{StartLine: 467, EndLine: 474}}},
		{ID: "debug@2.6.9", Name: "debug", Version: "2.6.9", Locations: []types.Location{{StartLine: 476, EndLine: 483}}},
		{ID: "debug@4.1.1", Name: "debug", Version: "4.1.1", Locations: []types.Location{{StartLine: 485, EndLine: 492}}},
		{ID: "decamelize@1.2.0", Name: "decamelize", Version: "1.2.0", Locations: []types.Location{{StartLine: 494, EndLine: 499}}},
		{ID: "define-properties@1.1.3", Name: "define-properties", Version: "1.1.3", Locations: []types.Location{{StartLine: 501, EndLine: 508}}},
		{ID: "delayed-stream@1.0.0", Name: "delayed-stream", Version: "1.0.0", Locations: []types.Location{{StartLine: 510, EndLine: 515}}},
		{ID: "delegates@1.0.0", Name: "delegates", Version: "1.0.0", Locations: []types.Location{{StartLine: 517, EndLine: 522}}},
		{ID: "depd@1.1.2", Name: "depd", Version: "1.1.2", Locations: []types.Location{{StartLine: 524, EndLine: 529}}},
		{ID: "destroy@1.0.4", Name: "destroy", Version: "1.0.4", Locations: []types.Location{{StartLine: 531, EndLine: 536}}},
		{ID: "diff@4.0.2", Name: "diff", Version: "4.0.2", Locations: []types.Location{{StartLine: 538, EndLine: 543}}},
		{ID: "ecc-jsbn@0.1.2", Name: "ecc-jsbn", Version: "0.1.2", Locations: []types.Location{{StartLine: 545, EndLine: 553}}},
		{ID: "ee-first@1.1.1", Name: "ee-first", Version: "1.1.1", Locations: []types.Location{{StartLine: 555, EndLine: 560}}},
		{ID: "emoji-regex@7.0.3", Name: "emoji-regex", Version: "7.0.3", Locations: []types.Location{{StartLine: 562, EndLine: 567}}},
		{ID: "encodeurl@1.0.2", Name: "encodeurl", Version: "1.0.2", Locations: []types.Location{{StartLine: 569, EndLine: 574}}},
		{ID: "env-paths@2.2.0", Name: "env-paths", Version: "2.2.0", Locations: []types.Location{{StartLine: 576, EndLine: 581}}},
		{ID: "es-abstract@1.17.6", Name: "es-abstract", Version: "1.17.6", Locations: []types.Location{{StartLine: 583, EndLine: 600}}},
		{ID: "es-array-method-boxes-properly@1.0.0", Name: "es-array-method-boxes-properly", Version: "1.0.0", Locations: []types.Location{{StartLine: 602, EndLine: 607}}},
		{ID: "es-get-iterator@1.1.0", Name: "es-get-iterator", Version: "1.1.0", Locations: []types.Location{{StartLine: 609, EndLine: 622}}},
		{ID: "es-to-primitive@1.2.1", Name: "es-to-primitive", Version: "1.2.1", Locations: []types.Location{{StartLine: 624, EndLine: 633}}},
		{ID: "escape-html@1.0.3", Name: "escape-html", Version: "1.0.3", Locations: []types.Location{{StartLine: 635, EndLine: 640}}},
		{ID: "escape-string-regexp@4.0.0", Name: "escape-string-regexp", Version: "4.0.0", Locations: []types.Location{{StartLine: 642, EndLine: 647}}},
		{ID: "esprima@4.0.1", Name: "esprima", Version: "4.0.1", Locations: []types.Location{{StartLine: 649, EndLine: 657}}},
		{ID: "etag@1.8.1", Name: "etag", Version: "1.8.1", Locations: []types.Location{{StartLine: 659, EndLine: 664}}},
		{ID: "express@4.17.1", Name: "express", Version: "4.17.1", Locations: []types.Location{{StartLine: 666, EndLine: 702}}},
		{ID: "extend@3.0.2", Name: "extend", Version: "3.0.2", Locations: []types.Location{{StartLine: 704, EndLine: 709}}},
		{ID: "extsprintf@1.3.0", Name: "extsprintf", Version: "1.3.0", Locations: []types.Location{{StartLine: 711, EndLine: 716}}},
		{ID: "fast-deep-equal@3.1.3", Name: "fast-deep-equal", Version: "3.1.3", Locations: []types.Location{{StartLine: 718, EndLine: 723}}},
		{ID: "fast-json-stable-stringify@2.1.0", Name: "fast-json-stable-stringify", Version: "2.1.0", Locations: []types.Location{{StartLine: 725, EndLine: 730}}},
		{ID: "fill-range@7.0.1", Name: "fill-range", Version: "7.0.1", Locations: []types.Location{{StartLine: 732, EndLine: 739}}},
		{ID: "finalhandler@1.1.2", Name: "finalhandler", Version: "1.1.2", Locations: []types.Location{{StartLine: 741, EndLine: 754}}},
		{ID: "find-up@5.0.0", Name: "find-up", Version: "5.0.0", Locations: []types.Location{{StartLine: 756, EndLine: 764}}},
		{ID: "find-up@3.0.0", Name: "find-up", Version: "3.0.0", Locations: []types.Location{{StartLine: 766, EndLine: 773}}},
		{ID: "flat@4.1.0", Name: "flat", Version: "4.1.0", Locations: []types.Location{{StartLine: 775, EndLine: 784}}},
		{ID: "follow-redirects@1.13.0", Name: "follow-redirects", Version: "1.13.0", Locations: []types.Location{{StartLine: 786, EndLine: 791}}},
		{ID: "forever-agent@0.6.1", Name: "forever-agent", Version: "0.6.1", Locations: []types.Location{{StartLine: 793, EndLine: 798}}},
		{ID: "form-data@2.3.3", Name: "form-data", Version: "2.3.3", Locations: []types.Location{{StartLine: 800, EndLine: 809}}},
		{ID: "forwarded@0.1.2", Name: "forwarded", Version: "0.1.2", Locations: []types.Location{{StartLine: 811, EndLine: 816}}},
		{ID: "fresh@0.5.2", Name: "fresh", Version: "0.5.2", Locations: []types.Location{{StartLine: 818, EndLine: 823}}},
		{ID: "fs-minipass@2.1.0", Name: "fs-minipass", Version: "2.1.0", Locations: []types.Location{{StartLine: 825, EndLine: 832}}},
		{ID: "fs.realpath@1.0.0", Name: "fs.realpath", Version: "1.0.0", Locations: []types.Location{{StartLine: 834, EndLine: 839}}},
		{ID: "fsevents@2.1.3", Name: "fsevents", Version: "2.1.3", Locations: []types.Location{{StartLine: 850, EndLine: 857}}},
		{ID: "function-bind@1.1.1", Name: "function-bind", Version: "1.1.1", Locations: []types.Location{{StartLine: 859, EndLine: 864}}},
		{ID: "gauge@2.7.4", Name: "gauge", Version: "2.7.4", Locations: []types.Location{{StartLine: 866, EndLine: 880}}},
		{ID: "get-caller-file@2.0.5", Name: "get-caller-file", Version: "2.0.5", Locations: []types.Location{{StartLine: 882, EndLine: 887}}},
		{ID: "getpass@0.1.7", Name: "getpass", Version: "0.1.7", Locations: []types.Location{{StartLine: 889, EndLine: 896}}},
		{ID: "glob-parent@5.1.1", Name: "glob-parent", Version: "5.1.1", Locations: []types.Location{{StartLine: 898, EndLine: 905}}},
		{ID: "glob@7.1.6", Name: "glob", Version: "7.1.6", Locations: []types.Location{{StartLine: 907, EndLine: 919}}},
		{ID: "graceful-fs@4.2.4", Name: "graceful-fs", Version: "4.2.4", Locations: []types.Location{{StartLine: 921, EndLine: 926}}},
		{ID: "growl@1.10.5", Name: "growl", Version: "1.10.5", Locations: []types.Location{{StartLine: 928, EndLine: 933}}},
		{ID: "har-schema@2.0.0", Name: "har-schema", Version: "2.0.0", Locations: []types.Location{{StartLine: 935, EndLine: 940}}},
		{ID: "har-validator@5.1.5", Name: "har-validator", Version: "5.1.5", Locations: []types.Location{{StartLine: 942, EndLine: 950}}},
		{ID: "has-flag@4.0.0", Name: "has-flag", Version: "4.0.0", Locations: []types.Location{{StartLine: 952, EndLine: 957}}},
		{ID: "has-symbols@1.0.1", Name: "has-symbols", Version: "1.0.1", Locations: []types.Location{{StartLine: 959, EndLine: 964}}},
		{ID: "has-unicode@2.0.1", Name: "has-unicode", Version: "2.0.1", Locations: []types.Location{{StartLine: 966, EndLine: 971}}},
		{ID: "has@1.0.3", Name: "has", Version: "1.0.3", Locations: []types.Location{{StartLine: 973, EndLine: 980}}},
		{ID: "he@1.2.0", Name: "he", Version: "1.2.0", Locations: []types.Location{{StartLine: 982, EndLine: 989}}},
		{ID: "http-errors@1.7.2", Name: "http-errors", Version: "1.7.2", Locations: []types.Location{{StartLine: 991, EndLine: 1002}}},
		{ID: "http-errors@1.7.3", Name: "http-errors", Version: "1.7.3", Locations: []types.Location{{StartLine: 1004, EndLine: 1015}}},
		{ID: "http-signature@1.2.0", Name: "http-signature", Version: "1.2.0", Locations: []types.Location{{StartLine: 1017, EndLine: 1026}}},
		{ID: "iconv-lite@0.4.24", Name: "iconv-lite", Version: "0.4.24", Locations: []types.Location{{StartLine: 1028, EndLine: 1035}}},
		{ID: "inflight@1.0.6", Name: "inflight", Version: "1.0.6", Locations: []types.Location{{StartLine: 1037, EndLine: 1045}}},
		{ID: "inherits@2.0.4", Name: "inherits", Version: "2.0.4", Locations: []types.Location{{StartLine: 1047, EndLine: 1052}}},
		{ID: "inherits@2.0.3", Name: "inherits", Version: "2.0.3", Locations: []types.Location{{StartLine: 1054, EndLine: 1059}}},
		{ID: "ipaddr.js@1.9.1", Name: "ipaddr.js", Version: "1.9.1", Locations: []types.Location{{StartLine: 1061, EndLine: 1066}}},
		{ID: "is-arguments@1.0.4", Name: "is-arguments", Version: "1.0.4", Locations: []types.Location{{StartLine: 1068, EndLine: 1073}}},
		{ID: "is-binary-path@2.1.0", Name: "is-binary-path", Version: "2.1.0", Locations: []types.Location{{StartLine: 1075, EndLine: 1082}}},
		{ID: "is-buffer@2.0.4", Name: "is-buffer", Version: "2.0.4", Locations: []types.Location{{StartLine: 1084, EndLine: 1089}}},
		{ID: "is-callable@1.2.0", Name: "is-callable", Version: "1.2.0", Locations: []types.Location{{StartLine: 1091, EndLine: 1096}}},
		{ID: "is-date-object@1.0.2", Name: "is-date-object", Version: "1.0.2", Locations: []types.Location{{StartLine: 1098, EndLine: 1103}}},
		{ID: "is-extglob@2.1.1", Name: "is-extglob", Version: "2.1.1", Locations: []types.Location{{StartLine: 1105, EndLine: 1110}}},
		{ID: "is-fullwidth-code-point@1.0.0", Name: "is-fullwidth-code-point", Version: "1.0.0", Locations: []types.Location{{StartLine: 1112, EndLine: 1119}}},
		{ID: "is-fullwidth-code-point@2.0.0", Name: "is-fullwidth-code-point", Version: "2.0.0", Locations: []types.Location{{StartLine: 1121, EndLine: 1126}}},
		{ID: "is-glob@4.0.1", Name: "is-glob", Version: "4.0.1", Locations: []types.Location{{StartLine: 1128, EndLine: 1135}}},
		{ID: "is-map@2.0.1", Name: "is-map", Version: "2.0.1", Locations: []types.Location{{StartLine: 1137, EndLine: 1142}}},
		{ID: "is-number@7.0.0", Name: "is-number", Version: "7.0.0", Locations: []types.Location{{StartLine: 1144, EndLine: 1149}}},
		{ID: "is-plain-obj@1.1.0", Name: "is-plain-obj", Version: "1.1.0", Locations: []types.Location{{StartLine: 1151, EndLine: 1156}}},
		{ID: "is-regex@1.1.1", Name: "is-regex", Version: "1.1.1", Locations: []types.Location{{StartLine: 1158, EndLine: 1165}}},
		{ID: "is-set@2.0.1", Name: "is-set", Version: "2.0.1", Locations: []types.Location{{StartLine: 1167, EndLine: 1172}}},
		{ID: "is-string@1.0.5", Name: "is-string", Version: "1.0.5", Locations: []types.Location{{StartLine: 1174, EndLine: 1179}}},
		{ID: "is-symbol@1.0.3", Name: "is-symbol", Version: "1.0.3", Locations: []types.Location{{StartLine: 1181, EndLine: 1188}}},
		{ID: "is-typedarray@1.0.0", Name: "is-typedarray", Version: "1.0.0", Locations: []types.Location{{StartLine: 1190, EndLine: 1195}}},
		{ID: "isarray@2.0.5", Name: "isarray", Version: "2.0.5", Locations: []types.Location{{StartLine: 1197, EndLine: 1202}}},
		{ID: "isarray@1.0.0", Name: "isarray", Version: "1.0.0", Locations: []types.Location{{StartLine: 1204, EndLine: 1209}}},
		{ID: "isexe@2.0.0", Name: "isexe", Version: "2.0.0", Locations: []types.Location{{StartLine: 1211, EndLine: 1216}}},
		{ID: "isstream@0.1.2", Name: "isstream", Version: "0.1.2", Locations: []types.Location{{StartLine: 1218, EndLine: 1223}}},
		{ID: "iterate-iterator@1.0.1", Name: "iterate-iterator", Version: "1.0.1", Locations: []types.Location{{StartLine: 1225, EndLine: 1230}}},
		{ID: "iterate-value@1.0.2", Name: "iterate-value", Version: "1.0.2", Locations: []types.Location{{StartLine: 1232, EndLine: 1240}}},
		{ID: "jquery@3.5.1", Name: "jquery", Version: "3.5.1", Locations: []types.Location{{StartLine: 1242, EndLine: 1247}}},
		{ID: "js-tokens@4.0.0", Name: "js-tokens", Version: "4.0.0", Locations: []types.Location{{StartLine: 1249, EndLine: 1254}}},
		{ID: "js-yaml@3.14.0", Name: "js-yaml", Version: "3.14.0", Locations: []types.Location{{StartLine: 1256, EndLine: 1266}}},
		{ID: "jsbn@0.1.1", Name: "jsbn", Version: "0.1.1", Locations: []types.Location{{StartLine: 1268, EndLine: 1273}}},
		{ID: "json-schema-traverse@0.4.1", Name: "json-schema-traverse", Version: "0.4.1", Locations: []types.Location{{StartLine: 1275, EndLine: 1280}}},
		{ID: "json-schema@0.2.3", Name: "json-schema", Version: "0.2.3", Locations: []types.Location{{StartLine: 1282, EndLine: 1287}}},
		{ID: "json-stringify-safe@5.0.1", Name: "json-stringify-safe", Version: "5.0.1", Locations: []types.Location{{StartLine: 1289, EndLine: 1294}}},
		{ID: "jsprim@1.4.1", Name: "jsprim", Version: "1.4.1", Locations: []types.Location{{StartLine: 1296, EndLine: 1306}}},
		{ID: "locate-path@3.0.0", Name: "locate-path", Version: "3.0.0", Locations: []types.Location{{StartLine: 1308, EndLine: 1316}}},
		{ID: "locate-path@6.0.0", Name: "locate-path", Version: "6.0.0", Locations: []types.Location{{StartLine: 1318, EndLine: 1325}}},
		{ID: "lodash@4.17.20", Name: "lodash", Version: "4.17.20", Locations: []types.Location{{StartLine: 1327, EndLine: 1332}}},
		{ID: "log-symbols@4.0.0", Name: "log-symbols", Version: "4.0.0", Locations: []types.Location{{StartLine: 1334, EndLine: 1341}}},
		{ID: "loose-envify@1.4.0", Name: "loose-envify", Version: "1.4.0", Locations: []types.Location{{StartLine: 1343, EndLine: 1352}}},
		{ID: "media-typer@0.3.0", Name: "media-typer", Version: "0.3.0", Locations: []types.Location{{StartLine: 1354, EndLine: 1359}}},
		{ID: "merge-descriptors@1.0.1", Name: "merge-descriptors", Version: "1.0.1", Locations: []types.Location{{StartLine: 1361, EndLine: 1366}}},
		{ID: "methods@1.1.2", Name: "methods", Version: "1.1.2", Locations: []types.Location{{StartLine: 1368, EndLine: 1373}}},
		{ID: "mime-db@1.44.0", Name: "mime-db", Version: "1.44.0", Locations: []types.Location{{StartLine: 1375, EndLine: 1380}}},
		{ID: "mime-types@2.1.27", Name: "mime-types", Version: "2.1.27", Locations: []types.Location{{StartLine: 1382, EndLine: 1389}}},
		{ID: "mime@1.6.0", Name: "mime", Version: "1.6.0", Locations: []types.Location{{StartLine: 1391, EndLine: 1398}}},
		{ID: "minimatch@3.0.4", Name: "minimatch", Version: "3.0.4", Locations: []types.Location{{StartLine: 1400, EndLine: 1407}}},
		{ID: "minipass@3.1.3", Name: "minipass", Version: "3.1.3", Locations: []types.Location{{StartLine: 1409, EndLine: 1416}}},
		{ID: "minizlib@2.1.2", Name: "minizlib", Version: "2.1.2", Locations: []types.Location{{StartLine: 1418, EndLine: 1426}}},
		{ID: "mkdirp@1.0.4", Name: "mkdirp", Version: "1.0.4", Locations: []types.Location{{StartLine: 1428, EndLine: 1435}}},
		{ID: "mocha@8.1.3", Name: "mocha", Version: "8.1.3", Locations: []types.Location{{StartLine: 1437, EndLine: 1471}}},
		{ID: "ms@2.0.0", Name: "ms", Version: "2.0.0", Locations: []types.Location{{StartLine: 1473, EndLine: 1478}}},
		{ID: "ms@2.1.1", Name: "ms", Version: "2.1.1", Locations: []types.Location{{StartLine: 1480, EndLine: 1485}}},
		{ID: "ms@2.1.2", Name: "ms", Version: "2.1.2", Locations: []types.Location{{StartLine: 1487, EndLine: 1492}}},
		{ID: "negotiator@0.6.2", Name: "negotiator", Version: "0.6.2", Locations: []types.Location{{StartLine: 1494, EndLine: 1499}}},
		{ID: "node-gyp@7.1.0", Name: "node-gyp", Version: "7.1.0", Locations: []types.Location{{StartLine: 1501, EndLine: 1519}}},
		{ID: "nopt@4.0.3", Name: "nopt", Version: "4.0.3", Locations: []types.Location{{StartLine: 1521, EndLine: 1531}}},
		{ID: "normalize-path@3.0.0", Name: "normalize-path", Version: "3.0.0", Locations: []types.Location{{StartLine: 1533, EndLine: 1538}}},
		{ID: "npmlog@4.1.2", Name: "npmlog", Version: "4.1.2", Locations: []types.Location{{StartLine: 1540, EndLine: 1550}}},
		{ID: "number-is-nan@1.0.1", Name: "number-is-nan", Version: "1.0.1", Locations: []types.Location{{StartLine: 1552, EndLine: 1557}}},
		{ID: "oauth-sign@0.9.0", Name: "oauth-sign", Version: "0.9.0", Locations: []types.Location{{StartLine: 1559, EndLine: 1564}}},
		{ID: "object-assign@4.1.1", Name: "object-assign", Version: "4.1.1", Locations: []types.Location{{StartLine: 1566, EndLine: 1571}}},
		{ID: "object-inspect@1.8.0", Name: "object-inspect", Version: "1.8.0", Locations: []types.Location{{StartLine: 1573, EndLine: 1578}}},
		{ID: "object-keys@1.1.1", Name: "object-keys", Version: "1.1.1", Locations: []types.Location{{StartLine: 1580, EndLine: 1585}}},
		{ID: "object.assign@4.1.0", Name: "object.assign", Version: "4.1.0", Locations: []types.Location{{StartLine: 1587, EndLine: 1597}}},
		{ID: "on-finished@2.3.0", Name: "on-finished", Version: "2.3.0", Locations: []types.Location{{StartLine: 1599, EndLine: 1606}}},
		{ID: "once@1.4.0", Name: "once", Version: "1.4.0", Locations: []types.Location{{StartLine: 1608, EndLine: 1615}}},
		{ID: "os-homedir@1.0.2", Name: "os-homedir", Version: "1.0.2", Locations: []types.Location{{StartLine: 1617, EndLine: 1622}}},
		{ID: "os-tmpdir@1.0.2", Name: "os-tmpdir", Version: "1.0.2", Locations: []types.Location{{StartLine: 1624, EndLine: 1629}}},
		{ID: "osenv@0.1.5", Name: "osenv", Version: "0.1.5", Locations: []types.Location{{StartLine: 1631, EndLine: 1639}}},
		{ID: "p-limit@2.3.0", Name: "p-limit", Version: "2.3.0", Locations: []types.Location{{StartLine: 1641, EndLine: 1648}}},
		{ID: "p-limit@3.0.2", Name: "p-limit", Version: "3.0.2", Locations: []types.Location{{StartLine: 1650, EndLine: 1657}}},
		{ID: "p-locate@3.0.0", Name: "p-locate", Version: "3.0.0", Locations: []types.Location{{StartLine: 1659, EndLine: 1666}}},
		{ID: "p-locate@5.0.0", Name: "p-locate", Version: "5.0.0", Locations: []types.Location{{StartLine: 1668, EndLine: 1675}}},
		{ID: "p-try@2.2.0", Name: "p-try", Version: "2.2.0", Locations: []types.Location{{StartLine: 1677, EndLine: 1682}}},
		{ID: "parseurl@1.3.3", Name: "parseurl", Version: "1.3.3", Locations: []types.Location{{StartLine: 1684, EndLine: 1689}}},
		{ID: "path-exists@3.0.0", Name: "path-exists", Version: "3.0.0", Locations: []types.Location{{StartLine: 1691, EndLine: 1696}}},
		{ID: "path-exists@4.0.0", Name: "path-exists", Version: "4.0.0", Locations: []types.Location{{StartLine: 1698, EndLine: 1703}}},
		{ID: "path-is-absolute@1.0.1", Name: "path-is-absolute", Version: "1.0.1", Locations: []types.Location{{StartLine: 1705, EndLine: 1710}}},
		{ID: "path-to-regexp@0.1.7", Name: "path-to-regexp", Version: "0.1.7", Locations: []types.Location{{StartLine: 1712, EndLine: 1717}}},
		{ID: "performance-now@2.1.0", Name: "performance-now", Version: "2.1.0", Locations: []types.Location{{StartLine: 1719, EndLine: 1724}}},
		{ID: "picomatch@2.2.2", Name: "picomatch", Version: "2.2.2", Locations: []types.Location{{StartLine: 1726, EndLine: 1731}}},
		{ID: "process-nextick-args@2.0.1", Name: "process-nextick-args", Version: "2.0.1", Locations: []types.Location{{StartLine: 1733, EndLine: 1738}}},
		{ID: "promise.allsettled@1.0.2", Name: "promise.allsettled", Version: "1.0.2", Locations: []types.Location{{StartLine: 1740, EndLine: 1751}}},
		{ID: "promise@8.1.0", Name: "promise", Version: "8.1.0", Locations: []types.Location{{StartLine: 1753, EndLine: 1760}}},
		{ID: "prop-types@15.7.2", Name: "prop-types", Version: "15.7.2", Locations: []types.Location{{StartLine: 1762, EndLine: 1771}}},
		{ID: "proxy-addr@2.0.6", Name: "proxy-addr", Version: "2.0.6", Locations: []types.Location{{StartLine: 1773, EndLine: 1781}}},
		{ID: "psl@1.8.0", Name: "psl", Version: "1.8.0", Locations: []types.Location{{StartLine: 1783, EndLine: 1788}}},
		{ID: "punycode@2.1.1", Name: "punycode", Version: "2.1.1", Locations: []types.Location{{StartLine: 1790, EndLine: 1795}}},
		{ID: "qs@6.7.0", Name: "qs", Version: "6.7.0", Locations: []types.Location{{StartLine: 1797, EndLine: 1802}}},
		{ID: "qs@6.5.2", Name: "qs", Version: "6.5.2", Locations: []types.Location{{StartLine: 1804, EndLine: 1809}}},
		{ID: "randombytes@2.1.0", Name: "randombytes", Version: "2.1.0", Locations: []types.Location{{StartLine: 1811, EndLine: 1818}}},
		{ID: "range-parser@1.2.1", Name: "range-parser", Version: "1.2.1", Locations: []types.Location{{StartLine: 1820, EndLine: 1825}}},
		{ID: "raw-body@2.4.0", Name: "raw-body", Version: "2.4.0", Locations: []types.Location{{StartLine: 1827, EndLine: 1837}}},
		{ID: "react-is@16.13.1", Name: "react-is", Version: "16.13.1", Locations: []types.Location{{StartLine: 1839, EndLine: 1844}}},
		{ID: "react@16.13.1", Name: "react", Version: "16.13.1", Locations: []types.Location{{StartLine: 1846, EndLine: 1855}}},
		{ID: "readable-stream@2.3.7", Name: "readable-stream", Version: "2.3.7", Locations: []types.Location{{StartLine: 1857, EndLine: 1870}}},
		{ID: "readdirp@3.4.0", Name: "readdirp", Version: "3.4.0", Locations: []types.Location{{StartLine: 1872, EndLine: 1879}}},
		{ID: "redux@4.0.5", Name: "redux", Version: "4.0.5", Locations: []types.Location{{StartLine: 1881, EndLine: 1889}}},
		{ID: "request@2.88.2", Name: "request", Version: "2.88.2", Locations: []types.Location{{StartLine: 1891, EndLine: 1917}}},
		{ID: "require-directory@2.1.1", Name: "require-directory", Version: "2.1.1", Locations: []types.Location{{StartLine: 1919, EndLine: 1924}}},
		{ID: "require-main-filename@2.0.0", Name: "require-main-filename", Version: "2.0.0", Locations: []types.Location{{StartLine: 1926, EndLine: 1931}}},
		{ID: "rimraf@2.7.1", Name: "rimraf", Version: "2.7.1", Locations: []types.Location{{StartLine: 1933, EndLine: 1942}}},
		{ID: "safe-buffer@5.1.2", Name: "safe-buffer", Version: "5.1.2", Locations: []types.Location{{StartLine: 1944, EndLine: 1949}}},
		{ID: "safe-buffer@5.2.1", Name: "safe-buffer", Version: "5.2.1", Locations: []types.Location{{StartLine: 1951, EndLine: 1956}}},
		{ID: "safer-buffer@2.1.2", Name: "safer-buffer", Version: "2.1.2", Locations: []types.Location{{StartLine: 1958, EndLine: 1963}}},
		{ID: "semver@7.3.2", Name: "semver", Version: "7.3.2", Locations: []types.Location{{StartLine: 1965, EndLine: 1972}}},
		{ID: "send@0.17.1", Name: "send", Version: "0.17.1", Locations: []types.Location{{StartLine: 1974, EndLine: 1993}}},
		{ID: "serialize-javascript@4.0.0", Name: "serialize-javascript", Version: "4.0.0", Locations: []types.Location{{StartLine: 1995, EndLine: 2002}}},
		{ID: "serve-static@1.14.1", Name: "serve-static", Version: "1.14.1", Locations: []types.Location{{StartLine: 2004, EndLine: 2014}}},
		{ID: "set-blocking@2.0.0", Name: "set-blocking", Version: "2.0.0", Locations: []types.Location{{StartLine: 2016, EndLine: 2021}}},
		{ID: "setprototypeof@1.1.1", Name: "setprototypeof", Version: "1.1.1", Locations: []types.Location{{StartLine: 2023, EndLine: 2028}}},
		{ID: "signal-exit@3.0.3", Name: "signal-exit", Version: "3.0.3", Locations: []types.Location{{StartLine: 2030, EndLine: 2035}}},
		{ID: "sprintf-js@1.0.3", Name: "sprintf-js", Version: "1.0.3", Locations: []types.Location{{StartLine: 2037, EndLine: 2042}}},
		{ID: "sshpk@1.16.1", Name: "sshpk", Version: "1.16.1", Locations: []types.Location{{StartLine: 2044, EndLine: 2063}}},
		{ID: "statuses@1.5.0", Name: "statuses", Version: "1.5.0", Locations: []types.Location{{StartLine: 2065, EndLine: 2070}}},
		{ID: "string-width@1.0.2", Name: "string-width", Version: "1.0.2", Locations: []types.Location{{StartLine: 2072, EndLine: 2081}}},
		{ID: "string-width@2.1.1", Name: "string-width", Version: "2.1.1", Locations: []types.Location{{StartLine: 2083, EndLine: 2091}}},
		{ID: "string-width@3.1.0", Name: "string-width", Version: "3.1.0", Locations: []types.Location{{StartLine: 2093, EndLine: 2102}}},
		{ID: "string.prototype.trimend@1.0.1", Name: "string.prototype.trimend", Version: "1.0.1", Locations: []types.Location{{StartLine: 2104, EndLine: 2112}}},
		{ID: "string.prototype.trimstart@1.0.1", Name: "string.prototype.trimstart", Version: "1.0.1", Locations: []types.Location{{StartLine: 2114, EndLine: 2122}}},
		{ID: "string_decoder@1.1.1", Name: "string_decoder", Version: "1.1.1", Locations: []types.Location{{StartLine: 2124, EndLine: 2131}}},
		{ID: "strip-ansi@3.0.1", Name: "strip-ansi", Version: "3.0.1", Locations: []types.Location{{StartLine: 2133, EndLine: 2140}}},
		{ID: "strip-ansi@4.0.0", Name: "strip-ansi", Version: "4.0.0", Locations: []types.Location{{StartLine: 2142, EndLine: 2149}}},
		{ID: "strip-ansi@5.2.0", Name: "strip-ansi", Version: "5.2.0", Locations: []types.Location{{StartLine: 2151, EndLine: 2158}}},
		{ID: "strip-json-comments@3.0.1", Name: "strip-json-comments", Version: "3.0.1", Locations: []types.Location{{StartLine: 2160, EndLine: 2165}}},
		{ID: "supports-color@7.1.0", Name: "supports-color", Version: "7.1.0", Locations: []types.Location{{StartLine: 2167, EndLine: 2174}}},
		{ID: "symbol-observable@1.2.0", Name: "symbol-observable", Version: "1.2.0", Locations: []types.Location{{StartLine: 2176, EndLine: 2181}}},
		{ID: "tar@6.0.5", Name: "tar", Version: "6.0.5", Locations: []types.Location{{StartLine: 2183, EndLine: 2195}}},
		{ID: "to-regex-range@5.0.1", Name: "to-regex-range", Version: "5.0.1", Locations: []types.Location{{StartLine: 2197, EndLine: 2204}}},
		{ID: "toidentifier@1.0.0", Name: "toidentifier", Version: "1.0.0", Locations: []types.Location{{StartLine: 2206, EndLine: 2211}}},
		{ID: "tough-cookie@2.5.0", Name: "tough-cookie", Version: "2.5.0", Locations: []types.Location{{StartLine: 2213, EndLine: 2221}}},
		{ID: "tunnel-agent@0.6.0", Name: "tunnel-agent", Version: "0.6.0", Locations: []types.Location{{StartLine: 2223, EndLine: 2230}}},
		{ID: "tweetnacl@0.14.5", Name: "tweetnacl", Version: "0.14.5", Locations: []types.Location{{StartLine: 2232, EndLine: 2237}}},
		{ID: "type-is@1.6.18", Name: "type-is", Version: "1.6.18", Locations: []types.Location{{StartLine: 2239, EndLine: 2247}}},
		{ID: "unpipe@1.0.0", Name: "unpipe", Version: "1.0.0", Locations: []types.Location{{StartLine: 2249, EndLine: 2254}}},
		{ID: "uri-js@4.4.0", Name: "uri-js", Version: "4.4.0", Locations: []types.Location{{StartLine: 2256, EndLine: 2263}}},
		{ID: "util-deprecate@1.0.2", Name: "util-deprecate", Version: "1.0.2", Locations: []types.Location{{StartLine: 2265, EndLine: 2270}}},
		{ID: "utils-merge@1.0.1", Name: "utils-merge", Version: "1.0.1", Locations: []types.Location{{StartLine: 2272, EndLine: 2277}}},
		{ID: "uuid@3.4.0", Name: "uuid", Version: "3.4.0", Locations: []types.Location{{StartLine: 2279, EndLine: 2286}}},
		{ID: "vary@1.1.2", Name: "vary", Version: "1.1.2", Locations: []types.Location{{StartLine: 2288, EndLine: 2293}}},
		{ID: "verror@1.10.0", Name: "verror", Version: "1.10.0", Locations: []types.Location{{StartLine: 2295, EndLine: 2304}}},
		{ID: "vue@2.6.12", Name: "vue", Version: "2.6.12", Locations: []types.Location{{StartLine: 2306, EndLine: 2311}}},
		{ID: "which-module@2.0.0", Name: "which-module", Version: "2.0.0", Locations: []types.Location{{StartLine: 2313, EndLine: 2318}}},
		{ID: "which@2.0.2", Name: "which", Version: "2.0.2", Locations: []types.Location{{StartLine: 2320, EndLine: 2329}}},
		{ID: "wide-align@1.1.3", Name: "wide-align", Version: "1.1.3", Locations: []types.Location{{StartLine: 2331, EndLine: 2338}}},
		{ID: "workerpool@6.0.0", Name: "workerpool", Version: "6.0.0", Locations: []types.Location{{StartLine: 2340, EndLine: 2345}}},
		{ID: "wrap-ansi@5.1.0", Name: "wrap-ansi", Version: "5.1.0", Locations: []types.Location{{StartLine: 2347, EndLine: 2356}}},
		{ID: "wrappy@1.0.2", Name: "wrappy", Version: "1.0.2", Locations: []types.Location{{StartLine: 2358, EndLine: 2363}}},
		{ID: "y18n@4.0.0", Name: "y18n", Version: "4.0.0", Locations: []types.Location{{StartLine: 2365, EndLine: 2370}}},
		{ID: "yallist@4.0.0", Name: "yallist", Version: "4.0.0", Locations: []types.Location{{StartLine: 2372, EndLine: 2377}}},
		{ID: "yargs-parser@13.1.2", Name: "yargs-parser", Version: "13.1.2", Locations: []types.Location{{StartLine: 2379, EndLine: 2387}}},
		{ID: "yargs-parser@15.0.1", Name: "yargs-parser", Version: "15.0.1", Locations: []types.Location{{StartLine: 2389, EndLine: 2397}}},
		{ID: "yargs-unparser@1.6.1", Name: "yargs-unparser", Version: "1.6.1", Locations: []types.Location{{StartLine: 2399, EndLine: 2410}}},
		{ID: "yargs@13.3.2", Name: "yargs", Version: "13.3.2", Locations: []types.Location{{StartLine: 2412, EndLine: 2428}}},
		{ID: "yargs@14.2.3", Name: "yargs", Version: "14.2.3", Locations: []types.Location{{StartLine: 2430, EndLine: 2447}}},
	}

	// ... and
	// node test_deps_generator/index.js yarn.lock
	yarnV2ManyDeps = []types.Dependency{
		{
			ID: "fsevents@2.1.3",
			DependsOn: []string{
				"node-gyp@7.1.0",
			},
		},
		{
			ID: "accepts@1.3.7",
			DependsOn: []string{
				"mime-types@2.1.27",
				"negotiator@0.6.2",
			},
		},
		{
			ID: "ajv@6.12.4",
			DependsOn: []string{
				"fast-deep-equal@3.1.3",
				"fast-json-stable-stringify@2.1.0",
				"json-schema-traverse@0.4.1",
				"uri-js@4.4.0",
			},
		},
		{
			ID: "ansi-styles@3.2.1",
			DependsOn: []string{
				"color-convert@1.9.3",
			},
		},
		{
			ID: "ansi-styles@4.2.1",
			DependsOn: []string{
				"@types/color-name@1.1.1",
				"color-convert@2.0.1",
			},
		},
		{
			ID: "anymatch@3.1.1",
			DependsOn: []string{
				"normalize-path@3.0.0",
				"picomatch@2.2.2",
			},
		},
		{
			ID: "are-we-there-yet@1.1.5",
			DependsOn: []string{
				"delegates@1.0.0",
				"readable-stream@2.3.7",
			},
		},
		{
			ID: "argparse@1.0.10",
			DependsOn: []string{
				"sprintf-js@1.0.3",
			},
		},
		{
			ID: "array.prototype.map@1.0.2",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.17.6",
				"es-array-method-boxes-properly@1.0.0",
				"is-string@1.0.5",
			},
		},
		{
			ID: "asn1@0.2.4",
			DependsOn: []string{
				"safer-buffer@2.1.2",
			},
		},
		{
			ID: "axios@0.20.0",
			DependsOn: []string{
				"follow-redirects@1.13.0",
			},
		},
		{
			ID: "bcrypt-pbkdf@1.0.2",
			DependsOn: []string{
				"tweetnacl@0.14.5",
			},
		},
		{
			ID: "body-parser@1.19.0",
			DependsOn: []string{
				"bytes@3.1.0",
				"content-type@1.0.4",
				"debug@2.6.9",
				"depd@1.1.2",
				"http-errors@1.7.2",
				"iconv-lite@0.4.24",
				"on-finished@2.3.0",
				"qs@6.7.0",
				"raw-body@2.4.0",
				"type-is@1.6.18",
			},
		},
		{
			ID: "brace-expansion@1.1.11",
			DependsOn: []string{
				"balanced-match@1.0.0",
				"concat-map@0.0.1",
			},
		},
		{
			ID: "braces@3.0.2",
			DependsOn: []string{
				"fill-range@7.0.1",
			},
		},
		{
			ID: "chalk@4.1.0",
			DependsOn: []string{
				"ansi-styles@4.2.1",
				"supports-color@7.1.0",
			},
		},
		{
			ID: "chokidar@3.4.2",
			DependsOn: []string{
				"anymatch@3.1.1",
				"braces@3.0.2",
				"fsevents@2.1.3",
				"glob-parent@5.1.1",
				"is-binary-path@2.1.0",
				"is-glob@4.0.1",
				"normalize-path@3.0.0",
				"readdirp@3.4.0",
			},
		},
		{
			ID: "cliui@5.0.0",
			DependsOn: []string{
				"string-width@3.1.0",
				"strip-ansi@5.2.0",
				"wrap-ansi@5.1.0",
			},
		},
		{
			ID: "color-convert@1.9.3",
			DependsOn: []string{
				"color-name@1.1.3",
			},
		},
		{
			ID: "color-convert@2.0.1",
			DependsOn: []string{
				"color-name@1.1.4",
			},
		},
		{
			ID: "combined-stream@1.0.8",
			DependsOn: []string{
				"delayed-stream@1.0.0",
			},
		},
		{
			ID: "content-disposition@0.5.3",
			DependsOn: []string{
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "dashdash@1.14.1",
			DependsOn: []string{
				"assert-plus@1.0.0",
			},
		},
		{
			ID: "debug@2.6.9",
			DependsOn: []string{
				"ms@2.0.0",
			},
		},
		{
			ID: "debug@4.1.1",
			DependsOn: []string{
				"ms@2.1.2",
			},
		},
		{
			ID: "define-properties@1.1.3",
			DependsOn: []string{
				"object-keys@1.1.1",
			},
		},
		{
			ID: "ecc-jsbn@0.1.2",
			DependsOn: []string{
				"jsbn@0.1.1",
				"safer-buffer@2.1.2",
			},
		},
		{
			ID: "es-abstract@1.17.6",
			DependsOn: []string{
				"es-to-primitive@1.2.1",
				"function-bind@1.1.1",
				"has@1.0.3",
				"has-symbols@1.0.1",
				"is-callable@1.2.0",
				"is-regex@1.1.1",
				"object-inspect@1.8.0",
				"object-keys@1.1.1",
				"object.assign@4.1.0",
				"string.prototype.trimend@1.0.1",
				"string.prototype.trimstart@1.0.1",
			},
		},
		{
			ID: "es-get-iterator@1.1.0",
			DependsOn: []string{
				"es-abstract@1.17.6",
				"has-symbols@1.0.1",
				"is-arguments@1.0.4",
				"is-map@2.0.1",
				"is-set@2.0.1",
				"is-string@1.0.5",
				"isarray@2.0.5",
			},
		},
		{
			ID: "es-to-primitive@1.2.1",
			DependsOn: []string{
				"is-callable@1.2.0",
				"is-date-object@1.0.2",
				"is-symbol@1.0.3",
			},
		},
		{
			ID: "express@4.17.1",
			DependsOn: []string{
				"accepts@1.3.7",
				"array-flatten@1.1.1",
				"body-parser@1.19.0",
				"content-disposition@0.5.3",
				"content-type@1.0.4",
				"cookie@0.4.0",
				"cookie-signature@1.0.6",
				"debug@2.6.9",
				"depd@1.1.2",
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"etag@1.8.1",
				"finalhandler@1.1.2",
				"fresh@0.5.2",
				"merge-descriptors@1.0.1",
				"methods@1.1.2",
				"on-finished@2.3.0",
				"parseurl@1.3.3",
				"path-to-regexp@0.1.7",
				"proxy-addr@2.0.6",
				"qs@6.7.0",
				"range-parser@1.2.1",
				"safe-buffer@5.1.2",
				"send@0.17.1",
				"serve-static@1.14.1",
				"setprototypeof@1.1.1",
				"statuses@1.5.0",
				"type-is@1.6.18",
				"utils-merge@1.0.1",
				"vary@1.1.2",
			},
		},
		{
			ID: "fill-range@7.0.1",
			DependsOn: []string{
				"to-regex-range@5.0.1",
			},
		},
		{
			ID: "finalhandler@1.1.2",
			DependsOn: []string{
				"debug@2.6.9",
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"on-finished@2.3.0",
				"parseurl@1.3.3",
				"statuses@1.5.0",
				"unpipe@1.0.0",
			},
		},
		{
			ID: "find-up@5.0.0",
			DependsOn: []string{
				"locate-path@6.0.0",
				"path-exists@4.0.0",
			},
		},
		{
			ID: "find-up@3.0.0",
			DependsOn: []string{
				"locate-path@3.0.0",
			},
		},
		{
			ID: "flat@4.1.0",
			DependsOn: []string{
				"is-buffer@2.0.4",
			},
		},
		{
			ID: "form-data@2.3.3",
			DependsOn: []string{
				"asynckit@0.4.0",
				"combined-stream@1.0.8",
				"mime-types@2.1.27",
			},
		},
		{
			ID: "fs-minipass@2.1.0",
			DependsOn: []string{
				"minipass@3.1.3",
			},
		},
		{
			ID: "gauge@2.7.4",
			DependsOn: []string{
				"aproba@1.2.0",
				"console-control-strings@1.1.0",
				"has-unicode@2.0.1",
				"object-assign@4.1.1",
				"signal-exit@3.0.3",
				"string-width@1.0.2",
				"strip-ansi@3.0.1",
				"wide-align@1.1.3",
			},
		},
		{
			ID: "getpass@0.1.7",
			DependsOn: []string{
				"assert-plus@1.0.0",
			},
		},
		{
			ID: "glob-parent@5.1.1",
			DependsOn: []string{
				"is-glob@4.0.1",
			},
		},
		{
			ID: "glob@7.1.6",
			DependsOn: []string{
				"fs.realpath@1.0.0",
				"inflight@1.0.6",
				"inherits@2.0.4",
				"minimatch@3.0.4",
				"once@1.4.0",
				"path-is-absolute@1.0.1",
			},
		},
		{
			ID: "har-validator@5.1.5",
			DependsOn: []string{
				"ajv@6.12.4",
				"har-schema@2.0.0",
			},
		},
		{
			ID: "has@1.0.3",
			DependsOn: []string{
				"function-bind@1.1.1",
			},
		},
		{
			ID: "http-errors@1.7.2",
			DependsOn: []string{
				"depd@1.1.2",
				"inherits@2.0.3",
				"setprototypeof@1.1.1",
				"statuses@1.5.0",
				"toidentifier@1.0.0",
			},
		},
		{
			ID: "http-errors@1.7.3",
			DependsOn: []string{
				"depd@1.1.2",
				"inherits@2.0.4",
				"setprototypeof@1.1.1",
				"statuses@1.5.0",
				"toidentifier@1.0.0",
			},
		},
		{
			ID: "http-signature@1.2.0",
			DependsOn: []string{
				"assert-plus@1.0.0",
				"jsprim@1.4.1",
				"sshpk@1.16.1",
			},
		},
		{
			ID: "iconv-lite@0.4.24",
			DependsOn: []string{
				"safer-buffer@2.1.2",
			},
		},
		{
			ID: "inflight@1.0.6",
			DependsOn: []string{
				"once@1.4.0",
				"wrappy@1.0.2",
			},
		},
		{
			ID: "is-binary-path@2.1.0",
			DependsOn: []string{
				"binary-extensions@2.1.0",
			},
		},
		{
			ID: "is-fullwidth-code-point@1.0.0",
			DependsOn: []string{
				"number-is-nan@1.0.1",
			},
		},
		{
			ID: "is-glob@4.0.1",
			DependsOn: []string{
				"is-extglob@2.1.1",
			},
		},
		{
			ID: "is-regex@1.1.1",
			DependsOn: []string{
				"has-symbols@1.0.1",
			},
		},
		{
			ID: "is-symbol@1.0.3",
			DependsOn: []string{
				"has-symbols@1.0.1",
			},
		},
		{
			ID: "iterate-value@1.0.2",
			DependsOn: []string{
				"es-get-iterator@1.1.0",
				"iterate-iterator@1.0.1",
			},
		},
		{
			ID: "js-yaml@3.14.0",
			DependsOn: []string{
				"argparse@1.0.10",
				"esprima@4.0.1",
			},
		},
		{
			ID: "jsprim@1.4.1",
			DependsOn: []string{
				"assert-plus@1.0.0",
				"extsprintf@1.3.0",
				"json-schema@0.2.3",
				"verror@1.10.0",
			},
		},
		{
			ID: "locate-path@3.0.0",
			DependsOn: []string{
				"p-locate@3.0.0",
				"path-exists@3.0.0",
			},
		},
		{
			ID: "locate-path@6.0.0",
			DependsOn: []string{
				"p-locate@5.0.0",
			},
		},
		{
			ID: "log-symbols@4.0.0",
			DependsOn: []string{
				"chalk@4.1.0",
			},
		},
		{
			ID: "loose-envify@1.4.0",
			DependsOn: []string{
				"js-tokens@4.0.0",
			},
		},
		{
			ID: "mime-types@2.1.27",
			DependsOn: []string{
				"mime-db@1.44.0",
			},
		},
		{
			ID: "minimatch@3.0.4",
			DependsOn: []string{
				"brace-expansion@1.1.11",
			},
		},
		{
			ID: "minipass@3.1.3",
			DependsOn: []string{
				"yallist@4.0.0",
			},
		},
		{
			ID: "minizlib@2.1.2",
			DependsOn: []string{
				"minipass@3.1.3",
				"yallist@4.0.0",
			},
		},
		{
			ID: "mocha@8.1.3",
			DependsOn: []string{
				"ansi-colors@4.1.1",
				"browser-stdout@1.3.1",
				"chokidar@3.4.2",
				"debug@4.1.1",
				"diff@4.0.2",
				"escape-string-regexp@4.0.0",
				"find-up@5.0.0",
				"glob@7.1.6",
				"growl@1.10.5",
				"he@1.2.0",
				"js-yaml@3.14.0",
				"log-symbols@4.0.0",
				"minimatch@3.0.4",
				"ms@2.1.2",
				"object.assign@4.1.0",
				"promise.allsettled@1.0.2",
				"serialize-javascript@4.0.0",
				"strip-json-comments@3.0.1",
				"supports-color@7.1.0",
				"which@2.0.2",
				"wide-align@1.1.3",
				"workerpool@6.0.0",
				"yargs@13.3.2",
				"yargs-parser@13.1.2",
				"yargs-unparser@1.6.1",
			},
		},
		{
			ID: "node-gyp@7.1.0",
			DependsOn: []string{
				"env-paths@2.2.0",
				"glob@7.1.6",
				"graceful-fs@4.2.4",
				"nopt@4.0.3",
				"npmlog@4.1.2",
				"request@2.88.2",
				"rimraf@2.7.1",
				"semver@7.3.2",
				"tar@6.0.5",
				"which@2.0.2",
			},
		},
		{
			ID: "nopt@4.0.3",
			DependsOn: []string{
				"abbrev@1.1.1",
				"osenv@0.1.5",
			},
		},
		{
			ID: "npmlog@4.1.2",
			DependsOn: []string{
				"are-we-there-yet@1.1.5",
				"console-control-strings@1.1.0",
				"gauge@2.7.4",
				"set-blocking@2.0.0",
			},
		},
		{
			ID: "object.assign@4.1.0",
			DependsOn: []string{
				"define-properties@1.1.3",
				"function-bind@1.1.1",
				"has-symbols@1.0.1",
				"object-keys@1.1.1",
			},
		},
		{
			ID: "on-finished@2.3.0",
			DependsOn: []string{
				"ee-first@1.1.1",
			},
		},
		{
			ID: "once@1.4.0",
			DependsOn: []string{
				"wrappy@1.0.2",
			},
		},
		{
			ID: "osenv@0.1.5",
			DependsOn: []string{
				"os-homedir@1.0.2",
				"os-tmpdir@1.0.2",
			},
		},
		{
			ID: "p-limit@2.3.0",
			DependsOn: []string{
				"p-try@2.2.0",
			},
		},
		{
			ID: "p-limit@3.0.2",
			DependsOn: []string{
				"p-try@2.2.0",
			},
		},
		{
			ID: "p-locate@3.0.0",
			DependsOn: []string{
				"p-limit@2.3.0",
			},
		},
		{
			ID: "p-locate@5.0.0",
			DependsOn: []string{
				"p-limit@3.0.2",
			},
		},
		{
			ID: "promise.allsettled@1.0.2",
			DependsOn: []string{
				"array.prototype.map@1.0.2",
				"define-properties@1.1.3",
				"es-abstract@1.17.6",
				"function-bind@1.1.1",
				"iterate-value@1.0.2",
			},
		},
		{
			ID: "promise@8.1.0",
			DependsOn: []string{
				"asap@2.0.6",
			},
		},
		{
			ID: "prop-types@15.7.2",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"react-is@16.13.1",
			},
		},
		{
			ID: "proxy-addr@2.0.6",
			DependsOn: []string{
				"forwarded@0.1.2",
				"ipaddr.js@1.9.1",
			},
		},
		{
			ID: "randombytes@2.1.0",
			DependsOn: []string{
				"safe-buffer@5.2.1",
			},
		},
		{
			ID: "raw-body@2.4.0",
			DependsOn: []string{
				"bytes@3.1.0",
				"http-errors@1.7.2",
				"iconv-lite@0.4.24",
				"unpipe@1.0.0",
			},
		},
		{
			ID: "react@16.13.1",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"object-assign@4.1.1",
				"prop-types@15.7.2",
			},
		},
		{
			ID: "readable-stream@2.3.7",
			DependsOn: []string{
				"core-util-is@1.0.2",
				"inherits@2.0.4",
				"isarray@1.0.0",
				"process-nextick-args@2.0.1",
				"safe-buffer@5.1.2",
				"string_decoder@1.1.1",
				"util-deprecate@1.0.2",
			},
		},
		{
			ID: "readdirp@3.4.0",
			DependsOn: []string{
				"picomatch@2.2.2",
			},
		},
		{
			ID: "redux@4.0.5",
			DependsOn: []string{
				"loose-envify@1.4.0",
				"symbol-observable@1.2.0",
			},
		},
		{
			ID: "request@2.88.2",
			DependsOn: []string{
				"aws-sign2@0.7.0",
				"aws4@1.10.1",
				"caseless@0.12.0",
				"combined-stream@1.0.8",
				"extend@3.0.2",
				"forever-agent@0.6.1",
				"form-data@2.3.3",
				"har-validator@5.1.5",
				"http-signature@1.2.0",
				"is-typedarray@1.0.0",
				"isstream@0.1.2",
				"json-stringify-safe@5.0.1",
				"mime-types@2.1.27",
				"oauth-sign@0.9.0",
				"performance-now@2.1.0",
				"qs@6.5.2",
				"safe-buffer@5.2.1",
				"tough-cookie@2.5.0",
				"tunnel-agent@0.6.0",
				"uuid@3.4.0",
			},
		},
		{
			ID: "rimraf@2.7.1",
			DependsOn: []string{
				"glob@7.1.6",
			},
		},
		{
			ID: "send@0.17.1",
			DependsOn: []string{
				"debug@2.6.9",
				"depd@1.1.2",
				"destroy@1.0.4",
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"etag@1.8.1",
				"fresh@0.5.2",
				"http-errors@1.7.3",
				"mime@1.6.0",
				"ms@2.1.1",
				"on-finished@2.3.0",
				"range-parser@1.2.1",
				"statuses@1.5.0",
			},
		},
		{
			ID: "serialize-javascript@4.0.0",
			DependsOn: []string{
				"randombytes@2.1.0",
			},
		},
		{
			ID: "serve-static@1.14.1",
			DependsOn: []string{
				"encodeurl@1.0.2",
				"escape-html@1.0.3",
				"parseurl@1.3.3",
				"send@0.17.1",
			},
		},
		{
			ID: "sshpk@1.16.1",
			DependsOn: []string{
				"asn1@0.2.4",
				"assert-plus@1.0.0",
				"bcrypt-pbkdf@1.0.2",
				"dashdash@1.14.1",
				"ecc-jsbn@0.1.2",
				"getpass@0.1.7",
				"jsbn@0.1.1",
				"safer-buffer@2.1.2",
				"tweetnacl@0.14.5",
			},
		},
		{
			ID: "string-width@1.0.2",
			DependsOn: []string{
				"code-point-at@1.1.0",
				"is-fullwidth-code-point@1.0.0",
				"strip-ansi@3.0.1",
			},
		},
		{
			ID: "string-width@2.1.1",
			DependsOn: []string{
				"is-fullwidth-code-point@2.0.0",
				"strip-ansi@4.0.0",
			},
		},
		{
			ID: "string-width@3.1.0",
			DependsOn: []string{
				"emoji-regex@7.0.3",
				"is-fullwidth-code-point@2.0.0",
				"strip-ansi@5.2.0",
			},
		},
		{
			ID: "string.prototype.trimend@1.0.1",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.17.6",
			},
		},
		{
			ID: "string.prototype.trimstart@1.0.1",
			DependsOn: []string{
				"define-properties@1.1.3",
				"es-abstract@1.17.6",
			},
		},
		{
			ID: "string_decoder@1.1.1",
			DependsOn: []string{
				"safe-buffer@5.1.2",
			},
		},
		{
			ID: "strip-ansi@3.0.1",
			DependsOn: []string{
				"ansi-regex@2.1.1",
			},
		},
		{
			ID: "strip-ansi@4.0.0",
			DependsOn: []string{
				"ansi-regex@3.0.0",
			},
		},
		{
			ID: "strip-ansi@5.2.0",
			DependsOn: []string{
				"ansi-regex@4.1.0",
			},
		},
		{
			ID: "supports-color@7.1.0",
			DependsOn: []string{
				"has-flag@4.0.0",
			},
		},
		{
			ID: "tar@6.0.5",
			DependsOn: []string{
				"chownr@2.0.0",
				"fs-minipass@2.1.0",
				"minipass@3.1.3",
				"minizlib@2.1.2",
				"mkdirp@1.0.4",
				"yallist@4.0.0",
			},
		},
		{
			ID: "to-regex-range@5.0.1",
			DependsOn: []string{
				"is-number@7.0.0",
			},
		},
		{
			ID: "tough-cookie@2.5.0",
			DependsOn: []string{
				"psl@1.8.0",
				"punycode@2.1.1",
			},
		},
		{
			ID: "tunnel-agent@0.6.0",
			DependsOn: []string{
				"safe-buffer@5.2.1",
			},
		},
		{
			ID: "type-is@1.6.18",
			DependsOn: []string{
				"media-typer@0.3.0",
				"mime-types@2.1.27",
			},
		},
		{
			ID: "uri-js@4.4.0",
			DependsOn: []string{
				"punycode@2.1.1",
			},
		},
		{
			ID: "verror@1.10.0",
			DependsOn: []string{
				"assert-plus@1.0.0",
				"core-util-is@1.0.2",
				"extsprintf@1.3.0",
			},
		},
		{
			ID: "which@2.0.2",
			DependsOn: []string{
				"isexe@2.0.0",
			},
		},
		{
			ID: "wide-align@1.1.3",
			DependsOn: []string{
				"string-width@2.1.1",
			},
		},
		{
			ID: "wrap-ansi@5.1.0",
			DependsOn: []string{
				"ansi-styles@3.2.1",
				"string-width@3.1.0",
				"strip-ansi@5.2.0",
			},
		},
		{
			ID: "yargs-parser@13.1.2",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
			},
		},
		{
			ID: "yargs-parser@15.0.1",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
			},
		},
		{
			ID: "yargs-unparser@1.6.1",
			DependsOn: []string{
				"camelcase@5.3.1",
				"decamelize@1.2.0",
				"flat@4.1.0",
				"is-plain-obj@1.1.0",
				"yargs@14.2.3",
			},
		},
		{
			ID: "yargs@13.3.2",
			DependsOn: []string{
				"cliui@5.0.0",
				"find-up@3.0.0",
				"get-caller-file@2.0.5",
				"require-directory@2.1.1",
				"require-main-filename@2.0.0",
				"set-blocking@2.0.0",
				"string-width@3.1.0",
				"which-module@2.0.0",
				"y18n@4.0.0",
				"yargs-parser@13.1.2",
			},
		},
		{
			ID: "yargs@14.2.3",
			DependsOn: []string{
				"cliui@5.0.0",
				"decamelize@1.2.0",
				"find-up@3.0.0",
				"get-caller-file@2.0.5",
				"require-directory@2.1.1",
				"require-main-filename@2.0.0",
				"set-blocking@2.0.0",
				"string-width@3.1.0",
				"which-module@2.0.0",
				"y18n@4.0.0",
				"yargs-parser@15.0.1",
			},
		},
	}

	// docker run --name node --rm -it node:16-alpine sh
	// mkdir app && cd app
	// yarn init -y
	// yarn add jquery
	// npm install
	yarnWithNpm = []types.Library{
		{ID: "jquery@3.6.0", Name: "jquery", Version: "3.6.0", Locations: []types.Location{{StartLine: 1, EndLine: 4}}},
	}

	yarnBadProtocol = []types.Library{
		{ID: "jquery@3.4.1", Name: "jquery", Version: "3.4.1", Locations: []types.Location{{StartLine: 4, EndLine: 7}}},
	}

	// docker run --name node --rm -it node@sha256:226ad4a45572c340b25a580e4af43bf74bb8a5c8bc8c0b2f6838d41914734399 sh
	// mkdir app && cd app
	// yarn init -y
	// yarn set version berry
	// yarn add debug@4.3.4
	// libs and deps are filled manually
	yarnV2DepsWithProtocol = []types.Library{
		{ID: "debug@4.3.4", Name: "debug", Version: "4.3.4", Locations: []types.Location{{StartLine: 16, EndLine: 26}}},
		{ID: "ms@2.1.2", Name: "ms", Version: "2.1.2", Locations: []types.Location{{StartLine: 28, EndLine: 33}}},
	}

	yarnV2DepsWithProtocolDeps = []types.Dependency{
		{
			ID:        "debug@4.3.4",
			DependsOn: []string{"ms@2.1.2"},
		},
	}
)
