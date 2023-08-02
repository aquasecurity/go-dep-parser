package swift

import (
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []types.Library
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy-Package.resolved",
			want: []types.Library{
				{
					ID:        "Nimble@9.2.1",
					Name:      "Nimble",
					Version:   "9.2.1",
					Locations: []types.Location{{StartLine: 4, EndLine: 12}},
					ExternalReferences: []types.ExternalRef{
						{
							Type: types.RefGit,
							URL:  "https://github.com/Quick/Nimble.git",
						},
					},
				},
				{
					ID:        "Quick@7.0.0",
					Name:      "Quick",
					Version:   "7.0.0",
					Locations: []types.Location{{StartLine: 13, EndLine: 21}},
					ExternalReferences: []types.ExternalRef{
						{
							Type: types.RefGit,
							URL:  "https://github.com/Quick/Quick.git",
						},
					},
				},
				{
					ID:        "ReactiveSwift@7.1.1",
					Name:      "ReactiveSwift",
					Version:   "7.1.1",
					Locations: []types.Location{{StartLine: 22, EndLine: 30}},
					ExternalReferences: []types.ExternalRef{
						{
							Type: types.RefGit,
							URL:  "https://github.com/ReactiveCocoa/ReactiveSwift",
						},
					},
				},
			},
		},
		{
			name:      "empty",
			inputFile: "testdata/empty-Package.resolved",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			f, err := os.Open(tt.inputFile)
			assert.NoError(t, err)

			libs, _, err := parser.Parse(f)
			assert.NoError(t, err)
			assert.Equal(t, tt.want, libs)
		})
	}
}
