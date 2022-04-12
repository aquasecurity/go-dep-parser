package mod

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// execute go mod tidy in normal folder
	GoModNormal = []types.Library{
		{"github.com/aquasecurity/go-dep-parser", "0.0.0-20211224170007-df43bca6b6ff", ""},
		{"golang.org/x/xerrors", "0.0.0-20200804184101-5ec99f83aff1", ""},
		{"gopkg.in/yaml.v3", "3.0.0-20210107192922-496545a6307b", ""},
	}

	// execute go mod tidy in replaced folder
	GoModReplaced = []types.Library{
		{"github.com/aquasecurity/go-dep-parser", "0.0.0-20220406074731-71021a481237", ""},
		{"golang.org/x/xerrors", "0.0.0-20200804184101-5ec99f83aff1", ""},
	}

	// execute go mod tidy in replaced-with-version folder
	GoModReplacedWithVersion = []types.Library{
		{"github.com/aquasecurity/go-dep-parser", "0.0.0-20220406074731-71021a481237", ""},
		{"golang.org/x/xerrors", "0.0.0-20200804184101-5ec99f83aff1", ""},
	}

	// execute go mod tidy in replaced-with-version-mismatch folder
	GoModReplacedWithVersionMismatch = []types.Library{
		{"github.com/aquasecurity/go-dep-parser", "0.0.0-20211224170007-df43bca6b6ff", ""},
		{"golang.org/x/xerrors", "0.0.0-20200804184101-5ec99f83aff1", ""},
		{"gopkg.in/yaml.v3", "3.0.0-20210107192922-496545a6307b", ""},
	}

	// execute go mod tidy in replaced-with-local-path folder
	GoModReplacedWithLocalPath = []types.Library{
		{"github.com/aquasecurity/go-dep-parser", "0.0.0-20211224170007-df43bca6b6ff", ""},
		{"gopkg.in/yaml.v3", "3.0.0-20210107192922-496545a6307b", ""},
	}

	// execute go mod tidy in replaced-with-local-path-and-version folder
	GoModReplacedWithLocalPathAndVersion = []types.Library{
		{"github.com/aquasecurity/go-dep-parser", "0.0.0-20211224170007-df43bca6b6ff", ""},
		{"gopkg.in/yaml.v3", "3.0.0-20210107192922-496545a6307b", ""},
	}

	// execute go mod tidy in replaced-with-local-path-and-version-mismatch folder
	GoModReplacedWithLocalPathAndVersionMismatch = []types.Library{
		{"github.com/aquasecurity/go-dep-parser", "0.0.0-20211224170007-df43bca6b6ff", ""},
		{"golang.org/x/xerrors", "0.0.0-20200804184101-5ec99f83aff1", ""},
		{"gopkg.in/yaml.v3", "3.0.0-20210107192922-496545a6307b", ""},
	}
)
