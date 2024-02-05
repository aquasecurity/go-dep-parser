package pom

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ReadSettings(t *testing.T) {
	tests := []struct {
		name         string
		envs         map[string]string
		wantSettings settings
	}{
		{
			name: "happy path with only global settings",
			envs: map[string]string{
				"HOME":       "",
				"MAVEN_HOME": filepath.Join("testdata", "settings", "global"),
			},
			wantSettings: settings{
				LocalRepository: "testdata/repository",
				Servers: []Server{
					{
						ID: "global-server",
					},
					{
						ID:       "server-with-credentials",
						Username: "test-user",
						Password: "test-password-from-global",
					},
					{
						ID:       "server-with-name-only",
						Username: "test-user-only",
					},
				},
			},
		},
		{
			name: "happy path with only user settings",
			envs: map[string]string{
				"HOME":       filepath.Join("testdata", "settings", "user"),
				"MAVEN_HOME": "",
			},
			wantSettings: settings{
				LocalRepository: "testdata/user/repository",
				Servers: []Server{
					{
						ID: "user-server",
					},
					{
						ID:       "server-with-credentials",
						Username: "test-user",
						Password: "test-password",
					},
					{
						ID:       "server-with-name-only",
						Username: "test-user-only",
					},
				},
			},
		},
		{
			name: "happy path with global and user settings",
			envs: map[string]string{
				"HOME":       filepath.Join("testdata", "settings", "user"),
				"MAVEN_HOME": filepath.Join("testdata", "settings", "global"),
			},
			wantSettings: settings{
				LocalRepository: "testdata/user/repository",
				Servers: []Server{
					{
						ID: "global-server",
					},
					{
						ID:       "server-with-credentials",
						Username: "test-user",
						Password: "test-password-from-global",
					},
					{
						ID:       "server-with-name-only",
						Username: "test-user-only",
					},
					{
						ID: "user-server",
					},
					{
						ID:       "server-with-credentials",
						Username: "test-user",
						Password: "test-password",
					},
				},
			},
		},
		{
			name: "without settings",
			envs: map[string]string{
				"HOME":       "",
				"MAVEN_HOME": "",
			},
			wantSettings: settings{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for env, settingsDir := range tt.envs {
				t.Setenv(env, settingsDir)
			}

			gotSettings := readSettings()
			require.Equal(t, tt.wantSettings, gotSettings)
		})
	}
}
