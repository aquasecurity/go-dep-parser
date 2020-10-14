package nuget

// The lockfile that nuget uses (packages.lock.json) works basically like this:
// Each 'build type' (for example .NETCoreApp,Version=v3.1) have a set of dependencies.
// Those dependencies can be 'Direct', 'Transitive' and 'Project'
// (meaning of those are quite self explanatory I think). The dependency consists of a string
// value key (package name) and an object, from which we need to fetch a few different values.
// The following values should be parsed right away: resolved (resolved version),
// type (this information might be worth having) and finally, it's dependencies.
// The dependencies in this stage of the file are only a string map where the key is package name
// and value is package version.

type LockFile struct {
	Dependencies map[string]Dependency
}

type Dependency struct {
	Type string
	Resolved string
	Dependencies map[string]string
}

