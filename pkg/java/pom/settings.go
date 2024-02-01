package pom

import (
	"encoding/xml"
	"os"
	"path/filepath"

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

	mavenHome, found := os.LookupEnv("MAVEN_HOME")
	if !found {
		mavenHome = "/usr/share/maven"
	}
	globalSettingsPath := filepath.Join(mavenHome, "conf", "settings.xml")
	globalSettings, err := openSettings(globalSettingsPath)
	if err == nil {
		s = globalSettings
	}

	userSettingsPath := filepath.Join(os.Getenv("HOME"), ".m2", "settings.xml")
	userSettings, err := openSettings(userSettingsPath)
	if err == nil {
		if userSettings.LocalRepository != "" {
			s.LocalRepository = userSettings.LocalRepository
		}
		s.Servers = append(s.Servers, userSettings.Servers...)
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
