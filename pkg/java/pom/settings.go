package pom

import (
	"encoding/xml"
	"os"
	"path/filepath"

	"github.com/samber/lo"
	"golang.org/x/net/html/charset"
)

type Server struct {
	ID       string `xml:"id"`
	Username string `xml:"username"`
	Password string `xml:"password"`
}

type settings struct {
	LocalRepository string   `xml:"localRepository"`
	Servers         []Server `xml:"servers>server"`
}

func readSettings() settings {
	s := settings{}

	// Some package managers use this path by default
	mavenHome := "/usr/share/maven"
	if mHome := os.Getenv("MAVEN_HOME"); mHome != "" {
		mavenHome = mHome
	}
	globalSettingsPath := filepath.Join(mavenHome, "conf", "settings.xml")
	globalSettings, err := openSettings(globalSettingsPath)
	if err == nil {
		s = globalSettings
	}

	userSettingsPath := filepath.Join(os.Getenv("HOME"), ".m2", "settings.xml")
	userSettings, err := openSettings(userSettingsPath)
	if err == nil {
		// We need to merge global and user settings. User settings being dominant.
		// https://maven.apache.org/settings.html#quick-overview
		if userSettings.LocalRepository != "" {
			s.LocalRepository = userSettings.LocalRepository
		}

		// Global servers are checked before user servers
		// https://maven.apache.org/guides/mini/guide-multiple-repositories.html#repository-order
		for _, userServer := range userSettings.Servers {
			// It is possible that global server and user server use same ID, but different user/password.
			// In this case we need to save both servers.
			if !lo.Contains(s.Servers, userServer) {
				s.Servers = append(s.Servers, userServer)
			}
		}
	}

	return s
}

func openSettings(filePath string) (settings, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return settings{}, err
	}

	s := settings{}
	decoder := xml.NewDecoder(f)
	decoder.CharsetReader = charset.NewReaderLabel
	if err = decoder.Decode(&s); err != nil {
		return settings{}, err
	}
	return s, nil
}
