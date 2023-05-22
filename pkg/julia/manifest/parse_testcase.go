package julia

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	juliaV1_6Libs = []types.Library{
		{ID: "ade2ca70-3891-5945-98fb-dc099432e06a@unknown", Name: "Dates", Version: "unknown", Locations: []types.Location{{StartLine: 3, EndLine: 5}}},
		{ID: "682c06a0-de6a-54ab-a142-c8b1cf79cde6@0.21.4", Name: "JSON", Version: "0.21.4", Locations: []types.Location{{StartLine: 7, EndLine: 11}}},
		{ID: "a63ad114-7e13-5084-954f-fe012c677804@unknown", Name: "Mmap", Version: "unknown", Locations: []types.Location{{StartLine: 13, EndLine: 14}}},
		{ID: "69de0a69-1ddd-5017-9359-2bf0b02dc9f0@2.4.2", Name: "Parsers", Version: "2.4.2", Locations: []types.Location{{StartLine: 16, EndLine: 20}}},
		{ID: "de0858da-6303-5e67-8744-51eddeeeb8d7@unknown", Name: "Printf", Version: "unknown", Locations: []types.Location{{StartLine: 22, EndLine: 24}}},
		{ID: "4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5@unknown", Name: "Unicode", Version: "unknown", Locations: []types.Location{{StartLine: 26, EndLine: 27}}},
	}

	juliaV1_6Deps = []types.Dependency{
		{ID: "ade2ca70-3891-5945-98fb-dc099432e06a@unknown", DependsOn: []string{"de0858da-6303-5e67-8744-51eddeeeb8d7@unknown"}},
		{ID: "682c06a0-de6a-54ab-a142-c8b1cf79cde6@0.21.4", DependsOn: []string{
			"ade2ca70-3891-5945-98fb-dc099432e06a@unknown",
			"a63ad114-7e13-5084-954f-fe012c677804@unknown",
			"69de0a69-1ddd-5017-9359-2bf0b02dc9f0@2.4.2",
			"4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5@unknown",
		}},
		{ID: "69de0a69-1ddd-5017-9359-2bf0b02dc9f0@2.4.2", DependsOn: []string{"ade2ca70-3891-5945-98fb-dc099432e06a@unknown"}},
		{ID: "de0858da-6303-5e67-8744-51eddeeeb8d7@unknown", DependsOn: []string{"4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5@unknown"}},
	}

	juliaV1_8Libs = []types.Library{
		{ID: "ade2ca70-3891-5945-98fb-dc099432e06a@1.8.5", Name: "Dates", Version: "1.8.5", Locations: []types.Location{{StartLine: 7, EndLine: 9}}},
		{ID: "682c06a0-de6a-54ab-a142-c8b1cf79cde6@0.21.4", Name: "JSON", Version: "0.21.4", Locations: []types.Location{{StartLine: 11, EndLine: 15}}},
		{ID: "a63ad114-7e13-5084-954f-fe012c677804@1.8.5", Name: "Mmap", Version: "1.8.5", Locations: []types.Location{{StartLine: 17, EndLine: 18}}},
		{ID: "69de0a69-1ddd-5017-9359-2bf0b02dc9f0@2.5.10", Name: "Parsers", Version: "2.5.10", Locations: []types.Location{{StartLine: 20, EndLine: 24}}},
		{ID: "aea7be01-6a6a-4083-8856-8a6e6704d82a@1.1.1", Name: "PrecompileTools", Version: "1.1.1", Locations: []types.Location{{StartLine: 26, EndLine: 30}}},
		{ID: "21216c6a-2e73-6563-6e65-726566657250@1.4.0", Name: "Preferences", Version: "1.4.0", Locations: []types.Location{{StartLine: 32, EndLine: 36}}},
		{ID: "de0858da-6303-5e67-8744-51eddeeeb8d7@1.8.5", Name: "Printf", Version: "1.8.5", Locations: []types.Location{{StartLine: 38, EndLine: 40}}},
		{ID: "9a3f8284-a2c9-5f02-9a11-845980a1fd5c@1.8.5", Name: "Random", Version: "1.8.5", Locations: []types.Location{{StartLine: 42, EndLine: 44}}},
		{ID: "ea8e919c-243c-51af-8825-aaa63cd721ce@0.7.0", Name: "SHA", Version: "0.7.0", Locations: []types.Location{{StartLine: 46, EndLine: 48}}},
		{ID: "9e88b42a-f829-5b0c-bbe9-9e923198166b@1.8.5", Name: "Serialization", Version: "1.8.5", Locations: []types.Location{{StartLine: 50, EndLine: 51}}},
		{ID: "fa267f1f-6049-4f14-aa54-33bafae1ed76@1.0.0", Name: "TOML", Version: "1.0.0", Locations: []types.Location{{StartLine: 53, EndLine: 56}}},
		{ID: "cf7118a7-6976-5b1a-9a39-7adc72f591a4@1.8.5", Name: "UUIDs", Version: "1.8.5", Locations: []types.Location{{StartLine: 58, EndLine: 60}}},
		{ID: "4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5@1.8.5", Name: "Unicode", Version: "1.8.5", Locations: []types.Location{{StartLine: 62, EndLine: 63}}},
	}

	juliaV1_8Deps = []types.Dependency{
		{ID: "ade2ca70-3891-5945-98fb-dc099432e06a@1.8.5", DependsOn: []string{"de0858da-6303-5e67-8744-51eddeeeb8d7@1.8.5"}},
		{ID: "682c06a0-de6a-54ab-a142-c8b1cf79cde6@0.21.4", DependsOn: []string{
			"ade2ca70-3891-5945-98fb-dc099432e06a@1.8.5",
			"a63ad114-7e13-5084-954f-fe012c677804@1.8.5",
			"69de0a69-1ddd-5017-9359-2bf0b02dc9f0@2.5.10",
			"4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5@1.8.5",
		}},
		{ID: "69de0a69-1ddd-5017-9359-2bf0b02dc9f0@2.5.10", DependsOn: []string{"ade2ca70-3891-5945-98fb-dc099432e06a@1.8.5", "aea7be01-6a6a-4083-8856-8a6e6704d82a@1.1.1", "cf7118a7-6976-5b1a-9a39-7adc72f591a4@1.8.5"}},
		{ID: "aea7be01-6a6a-4083-8856-8a6e6704d82a@1.1.1", DependsOn: []string{"21216c6a-2e73-6563-6e65-726566657250@1.4.0"}},
		{ID: "21216c6a-2e73-6563-6e65-726566657250@1.4.0", DependsOn: []string{"fa267f1f-6049-4f14-aa54-33bafae1ed76@1.0.0"}},
		{ID: "de0858da-6303-5e67-8744-51eddeeeb8d7@1.8.5", DependsOn: []string{"4ec0a83e-493e-50e2-b9ac-8f72acf5a8f5@1.8.5"}},
		{ID: "9a3f8284-a2c9-5f02-9a11-845980a1fd5c@1.8.5", DependsOn: []string{"ea8e919c-243c-51af-8825-aaa63cd721ce@0.7.0", "9e88b42a-f829-5b0c-bbe9-9e923198166b@1.8.5"}},
		{ID: "fa267f1f-6049-4f14-aa54-33bafae1ed76@1.0.0", DependsOn: []string{"ade2ca70-3891-5945-98fb-dc099432e06a@1.8.5"}},
		{ID: "cf7118a7-6976-5b1a-9a39-7adc72f591a4@1.8.5", DependsOn: []string{"9a3f8284-a2c9-5f02-9a11-845980a1fd5c@1.8.5", "ea8e919c-243c-51af-8825-aaa63cd721ce@0.7.0"}},
	}
)
