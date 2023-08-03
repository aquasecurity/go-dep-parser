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
					Name:      "https://github.com/Quick/Nimble.git",
					Version:   "9.2.1",
					Locations: []types.Location{{StartLine: 4, EndLine: 12}},
				},
				{
					Name:      "https://github.com/Quick/Quick.git",
					Version:   "7.0.0",
					Locations: []types.Location{{StartLine: 13, EndLine: 21}},
				},
				{
					Name:      "https://github.com/ReactiveCocoa/ReactiveSwift",
					Version:   "7.1.1",
					Locations: []types.Location{{StartLine: 22, EndLine: 30}},
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
