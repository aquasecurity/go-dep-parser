package cargo

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// docker run --name cargo --rm -it rust:1.45 bash
	// apt -y update && apt -y install jq
	// export USER=cargo
	// cargo install cargo-edit
	// cargo init normal && cd normal
	// cargo add libc
	// cargo update
	// cargo metadata  | jq -rc '.packages[] | "{\"\(.name)\", \"\(.version)\", \"\"},"'
	cargoNormal = []types.Library{
		types.NewLibrary("normal", "0.1.0", ""),
		types.NewLibrary("libc", "0.2.54", ""),
	}

	// docker run --name cargo --rm -it rust:1.45 bash
	// apt -y update && apt -y install jq
	// export USER=cargo
	// cargo install cargo-edit
	// cargo init many && cd many
	// cargo add rand bitflags lazy_static log serde syn regex quote handlebars rocket
	// cargo update
	// cargo metadata  | jq -rc '.packages[] | "{\"\(.name)\", \"\(.version)\", \"\"},"'
	cargoMany = []types.Library{
		types.NewLibrary("many", "0.1.0", ""),
		types.NewLibrary("aho-corasick", "0.7.3", ""),
		types.NewLibrary("autocfg", "0.1.2", ""),
		types.NewLibrary("base64", "0.10.1", ""),
		types.NewLibrary("base64", "0.9.3", ""),
		types.NewLibrary("bitflags", "1.0.4", ""),
		types.NewLibrary("block-buffer", "0.7.3", ""),
		types.NewLibrary("block-padding", "0.1.4", ""),
		types.NewLibrary("byte-tools", "0.3.1", ""),
		types.NewLibrary("byteorder", "1.3.1", ""),
		types.NewLibrary("cc", "1.0.36", ""),
		types.NewLibrary("cfg-if", "0.1.7", ""),
		types.NewLibrary("cloudabi", "0.0.3", ""),
		types.NewLibrary("cookie", "0.11.1", ""),
		types.NewLibrary("devise", "0.2.0", ""),
		types.NewLibrary("devise_codegen", "0.2.0", ""),
		types.NewLibrary("devise_core", "0.2.0", ""),
		types.NewLibrary("digest", "0.8.0", ""),
		types.NewLibrary("fake-simd", "0.1.2", ""),
		types.NewLibrary("fuchsia-cprng", "0.1.1", ""),
		types.NewLibrary("generic-array", "0.12.0", ""),
		types.NewLibrary("handlebars", "1.1.0", ""),
		types.NewLibrary("httparse", "1.3.3", ""),
		types.NewLibrary("hyper", "0.10.16", ""),
		types.NewLibrary("idna", "0.1.5", ""),
		types.NewLibrary("indexmap", "1.0.2", ""),
		types.NewLibrary("isatty", "0.1.9", ""),
		types.NewLibrary("itoa", "0.4.4", ""),
		types.NewLibrary("language-tags", "0.2.2", ""),
		types.NewLibrary("lazy_static", "1.3.0", ""),
		types.NewLibrary("libc", "0.2.54", ""),
		types.NewLibrary("log", "0.3.9", ""),
		types.NewLibrary("log", "0.4.6", ""),
		types.NewLibrary("maplit", "1.0.1", ""),
		types.NewLibrary("matches", "0.1.8", ""),
		types.NewLibrary("memchr", "2.2.0", ""),
		types.NewLibrary("mime", "0.2.6", ""),
		types.NewLibrary("num_cpus", "1.10.0", ""),
		types.NewLibrary("opaque-debug", "0.2.2", ""),
		types.NewLibrary("pear", "0.1.2", ""),
		types.NewLibrary("pear_codegen", "0.1.2", ""),
		types.NewLibrary("percent-encoding", "1.0.1", ""),
		types.NewLibrary("pest", "2.1.1", ""),
		types.NewLibrary("pest_derive", "2.1.0", ""),
		types.NewLibrary("pest_generator", "2.1.0", ""),
		types.NewLibrary("pest_meta", "2.1.1", ""),
		types.NewLibrary("proc-macro2", "0.4.30", ""),
		types.NewLibrary("quick-error", "1.2.2", ""),
		types.NewLibrary("quote", "0.6.12", ""),
		types.NewLibrary("rand", "0.6.5", ""),
		types.NewLibrary("rand_chacha", "0.1.1", ""),
		types.NewLibrary("rand_core", "0.3.1", ""),
		types.NewLibrary("rand_core", "0.4.0", ""),
		types.NewLibrary("rand_hc", "0.1.0", ""),
		types.NewLibrary("rand_isaac", "0.1.1", ""),
		types.NewLibrary("rand_jitter", "0.1.4", ""),
		types.NewLibrary("rand_os", "0.1.3", ""),
		types.NewLibrary("rand_pcg", "0.1.2", ""),
		types.NewLibrary("rand_xorshift", "0.1.1", ""),
		types.NewLibrary("rdrand", "0.4.0", ""),
		types.NewLibrary("redox_syscall", "0.1.54", ""),
		types.NewLibrary("regex", "1.1.6", ""),
		types.NewLibrary("regex-syntax", "0.6.6", ""),
		types.NewLibrary("ring", "0.13.5", ""),
		types.NewLibrary("rocket", "0.4.0", ""),
		types.NewLibrary("rocket_codegen", "0.4.0", ""),
		types.NewLibrary("rocket_http", "0.4.0", ""),
		types.NewLibrary("ryu", "0.2.8", ""),
		types.NewLibrary("safemem", "0.3.0", ""),
		types.NewLibrary("same-file", "1.0.4", ""),
		types.NewLibrary("serde", "1.0.91", ""),
		types.NewLibrary("serde_json", "1.0.39", ""),
		types.NewLibrary("sha-1", "0.8.1", ""),
		types.NewLibrary("smallvec", "0.6.9", ""),
		types.NewLibrary("state", "0.4.1", ""),
		types.NewLibrary("syn", "0.15.34", ""),
		types.NewLibrary("thread_local", "0.3.6", ""),
		types.NewLibrary("time", "0.1.42", ""),
		types.NewLibrary("toml", "0.4.10", ""),
		types.NewLibrary("traitobject", "0.1.0", ""),
		types.NewLibrary("typeable", "0.1.2", ""),
		types.NewLibrary("typenum", "1.10.0", ""),
		types.NewLibrary("ucd-trie", "0.1.1", ""),
		types.NewLibrary("ucd-util", "0.1.3", ""),
		types.NewLibrary("unicase", "1.4.2", ""),
		types.NewLibrary("unicode-bidi", "0.3.4", ""),
		types.NewLibrary("unicode-normalization", "0.1.8", ""),
		types.NewLibrary("unicode-xid", "0.1.0", ""),
		types.NewLibrary("untrusted", "0.6.2", ""),
		types.NewLibrary("url", "1.7.2", ""),
		types.NewLibrary("utf8-ranges", "1.0.2", ""),
		types.NewLibrary("version_check", "0.1.5", ""),
		types.NewLibrary("walkdir", "2.2.7", ""),
		types.NewLibrary("winapi", "0.3.7", ""),
		types.NewLibrary("winapi-i686-pc-windows-gnu", "0.4.0", ""),
		types.NewLibrary("winapi-util", "0.1.2", ""),
		types.NewLibrary("winapi-x86_64-pc-windows-gnu", "0.4.0", ""),
		types.NewLibrary("yansi", "0.4.0", ""),
		types.NewLibrary("yansi", "0.5.0", ""),
	}

	// docker run --name cargo --rm -it rust:1.45 bash
	// apt -y update && apt -y install jq
	// export USER=cargo
	// cargo install cargo-edit
	// cargo init web && cd web
	// cargo add nickel
	// cargo update
	// cargo metadata  | jq -rc '.packages[] | "{\"\(.name)\", \"\(.version)\", \"\"},"'
	cargoNickel = []types.Library{
		types.NewLibrary("web", "0.1.0", ""),
		types.NewLibrary("aho-corasick", "0.7.3", ""),
		types.NewLibrary("base64", "0.9.3", ""),
		types.NewLibrary("byteorder", "1.3.1", ""),
		types.NewLibrary("cfg-if", "0.1.7", ""),
		types.NewLibrary("groupable", "0.2.0", ""),
		types.NewLibrary("httparse", "1.3.3", ""),
		types.NewLibrary("hyper", "0.10.16", ""),
		types.NewLibrary("idna", "0.1.5", ""),
		types.NewLibrary("itoa", "0.4.4", ""),
		types.NewLibrary("language-tags", "0.2.2", ""),
		types.NewLibrary("lazy_static", "1.3.0", ""),
		types.NewLibrary("libc", "0.2.54", ""),
		types.NewLibrary("log", "0.3.9", ""),
		types.NewLibrary("log", "0.4.6", ""),
		types.NewLibrary("matches", "0.1.8", ""),
		types.NewLibrary("memchr", "2.2.0", ""),
		types.NewLibrary("mime", "0.2.6", ""),
		types.NewLibrary("modifier", "0.1.0", ""),
		types.NewLibrary("mustache", "0.9.0", ""),
		types.NewLibrary("nickel", "0.11.0", ""),
		types.NewLibrary("num_cpus", "1.10.0", ""),
		types.NewLibrary("percent-encoding", "1.0.1", ""),
		types.NewLibrary("plugin", "0.2.6", ""),
		types.NewLibrary("redox_syscall", "0.1.54", ""),
		types.NewLibrary("regex", "1.1.6", ""),
		types.NewLibrary("regex-syntax", "0.6.6", ""),
		types.NewLibrary("ryu", "0.2.8", ""),
		types.NewLibrary("safemem", "0.3.0", ""),
		types.NewLibrary("serde", "1.0.91", ""),
		types.NewLibrary("serde_json", "1.0.39", ""),
		types.NewLibrary("smallvec", "0.6.9", ""),
		types.NewLibrary("thread_local", "0.3.6", ""),
		types.NewLibrary("time", "0.1.42", ""),
		types.NewLibrary("traitobject", "0.1.0", ""),
		types.NewLibrary("typeable", "0.1.2", ""),
		types.NewLibrary("typemap", "0.3.3", ""),
		types.NewLibrary("ucd-util", "0.1.3", ""),
		types.NewLibrary("unicase", "1.4.2", ""),
		types.NewLibrary("unicode-bidi", "0.3.4", ""),
		types.NewLibrary("unicode-normalization", "0.1.8", ""),
		types.NewLibrary("unsafe-any", "0.4.2", ""),
		types.NewLibrary("url", "1.7.2", ""),
		types.NewLibrary("utf8-ranges", "1.0.2", ""),
		types.NewLibrary("version_check", "0.1.5", ""),
		types.NewLibrary("winapi", "0.3.7", ""),
		types.NewLibrary("winapi-i686-pc-windows-gnu", "0.4.0", ""),
		types.NewLibrary("winapi-x86_64-pc-windows-gnu", "0.4.0", ""),
	}
)
