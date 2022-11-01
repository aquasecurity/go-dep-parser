package meta_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/conda/meta"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input   string
		want    []types.Library
		wantErr bool
	}{
		{
			input: "testdata/_libgcc_mutex-0.1-main.json",
			want:  []types.Library{{Name: "_libgcc_mutex", Version: "0.1"}},
		},
		{
			input: "testdata/_openmp_mutex-5.1-1_gnu.json",
			want:  []types.Library{{Name: "_openmp_mutex", Version: "5.1", License: "BSD-3-Clause"}},
		},
		{
			input: "testdata/ca-certificates-2022.10.11-h06a4308_0.json",
			want:  []types.Library{{Name: "ca-certificates", Version: "2022.10.11", License: "MPL-2.0"}},
		},
		{
			input: "testdata/certifi-2022.9.24-py38h06a4308_0.json",
			want:  []types.Library{{Name: "certifi", Version: "2022.9.24", License: "MPL-2.0"}},
		},
		{
			input: "testdata/ld_impl_linux-64-2.38-h1181459_1.json",
			want:  []types.Library{{Name: "ld_impl_linux-64", Version: "2.38", License: "GPL-3.0-only"}},
		},
		{
			input: "testdata/libffi-3.3-he6710b0_2.json",
			want:  []types.Library{{Name: "libffi", Version: "3.3", License: "Custom"}},
		},
		{
			input: "testdata/libgcc-ng-11.2.0-h1234567_1.json",
			want:  []types.Library{{Name: "libgcc-ng", Version: "11.2.0", License: "GPL-3.0-only WITH GCC-exception-3.1"}},
		},
		{
			input: "testdata/libgomp-11.2.0-h1234567_1.json",
			want:  []types.Library{{Name: "libgomp", Version: "11.2.0", License: "GPL-3.0-only WITH GCC-exception-3.1"}},
		},
		{
			input: "testdata/libstdcxx-ng-11.2.0-h1234567_1.json",
			want:  []types.Library{{Name: "libstdcxx-ng", Version: "11.2.0", License: "GPL-3.0-only WITH GCC-exception-3.1"}},
		},
		{
			input: "testdata/ncurses-6.3-h5eee18b_3.json",
			want:  []types.Library{{Name: "ncurses", Version: "6.3", License: "Free software (MIT-like)"}},
		},
		{
			input: "testdata/openssl-1.1.1q-h7f8727e_0.json",
			want:  []types.Library{{Name: "openssl", Version: "1.1.1q", License: "OpenSSL"}},
		},
		{
			input: "testdata/pip-22.2.2-py38h06a4308_0.json",
			want:  []types.Library{{Name: "pip", Version: "22.2.2", License: "MIT"}},
		},
		{
			input: "testdata/python-3.8.8-hdb3f193_5.json",
			want:  []types.Library{{Name: "python", Version: "3.8.8", License: "Python-2.0"}},
		},
		{
			input: "testdata/readline-8.2-h5eee18b_0.json",
			want:  []types.Library{{Name: "readline", Version: "8.2", License: "GPL-3.0-only"}},
		},
		{
			input: "testdata/setuptools-65.5.0-py38h06a4308_0.json",
			want:  []types.Library{{Name: "setuptools", Version: "65.5.0", License: "MIT"}},
		},
		{
			input: "testdata/sqlite-3.39.3-h5082296_0.json",
			want:  []types.Library{{Name: "sqlite", Version: "3.39.3", License: "blessing"}},
		},
		{
			input: "testdata/tk-8.6.12-h1ccaba5_0.json",
			want:  []types.Library{{Name: "tk", Version: "8.6.12", License: "TCL"}},
		},
		{
			input: "testdata/wheel-0.37.1-pyhd3eb1b0_0.json",
			want:  []types.Library{{Name: "wheel", Version: "0.37.1", License: "MIT"}},
		},
		{
			input: "testdata/xz-5.2.6-h5eee18b_0.json",
			want:  []types.Library{{Name: "xz", Version: "5.2.6", License: "LGPL-2.1-or-later and GPL-2.0-or-later"}},
		},
		{
			input: "testdata/zlib-1.2.13-h5eee18b_0.json",
			want:  []types.Library{{Name: "zlib", Version: "1.2.13", License: "Zlib"}},
		},
		{
			input:   "testdata/invalid.json",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			f, err := os.Open(tt.input)
			require.NoError(t, err)

			got, _, err := meta.NewParser().Parse(f)
			var errMsg string
			if err != nil {
				errMsg = err.Error()
			}
			require.Equal(t, tt.wantErr, err != nil, errMsg)

			assert.Equal(t, tt.want, got)
		})
	}
}
