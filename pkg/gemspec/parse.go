package gemspec

import (
	"bufio"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

var (
	bwQuotes         = regexp.MustCompile(`['|"](.*?)['|"]`)
	gemSpec          = ".gemspec"
	gemStr           = ".name = "
	gemStrVer        = ".version = "
	gemStrLic        = ".licenses = "
	packageNameRegEx = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)
	versionRegEx     = regexp.MustCompile(`^[0-9.]+$`)
	fileNameVersion  = regexp.MustCompile(`^([\w_.\-]+)-([0-9.]+)$`)
)

func Parse(r io.Reader, filePath string) ([]types.Library, error) {
	var libs []types.Library
	scanner := bufio.NewScanner(r)
	var gemName string
	var gemVersion string
	var licenses []string
	for scanner.Scan() {
		line := scanner.Text()
		// check if the file is binary or not, if binary return
		if !utf8.ValidString(line) {
			return libs, nil
		}
		quotesList := bwQuotes.FindStringSubmatch(line)
		if len(quotesList) > 1 {
			line = strings.TrimSpace(line)
			if strings.Contains(line, gemStr) {
				gemName = quotesList[1]
			} else if strings.Contains(line, gemStrVer) {
				gemVersion = quotesList[1]
			} else if strings.Contains(line, gemStrLic) {
				licenseList := bwQuotes.FindAllStringSubmatch(line, -1)
				for _, license := range licenseList {
					licenses = append(licenses, strings.Replace(license[1], " ", "", -1))
				}
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}
	isVersionFound := false
	isPkgNameFound := false
	if packageNameRegEx.MatchString(gemName) {
		isPkgNameFound = true
	}
	if versionRegEx.MatchString(gemVersion) {
		isVersionFound = true
	}
	// If still we did not find the name from file or if package name has special characters,
	// try to take the name and version from gemspec file.
	// Else take name from previous directory
	dirPath, fileName := filepath.Split(filePath)
	if !isPkgNameFound || !isVersionFound {
		packageName := strings.TrimSuffix(fileName, gemSpec)
		packageNameVersion := fileNameVersion.FindStringSubmatch(packageName)
		if !isPkgNameFound && len(packageNameVersion) >= 3 && packageNameRegEx.MatchString(packageNameVersion[1]) {
			isPkgNameFound = true
			gemName = packageNameVersion[1]
		}
		if !isVersionFound && len(packageNameVersion) >= 3 && versionRegEx.MatchString(packageNameVersion[2]) {
			isVersionFound = true
			gemVersion = packageNameVersion[2]
		}
	}
	// Version is not as per standards then, take the version from directory name.
	if !isPkgNameFound || !isVersionFound {

		_, prevDirectory := filepath.Split(strings.TrimSuffix(dirPath, "/"))
		packageNameVersion := fileNameVersion.FindStringSubmatch(prevDirectory)
		if !isPkgNameFound && len(packageNameVersion) >= 3 && packageNameRegEx.MatchString(packageNameVersion[1]) {
			isPkgNameFound = true
			gemName = packageNameVersion[1]
		}
		if !isVersionFound && len(packageNameVersion) >= 3 && versionRegEx.MatchString(packageNameVersion[2]) {
			isVersionFound = true
			gemVersion = packageNameVersion[2]
		}
	}
	if isPkgNameFound && isVersionFound {
		libs = append(libs, types.Library{
			Name:    gemName,
			Version: gemVersion,
			License: strings.Join(licenses, ","),
		})
	}

	return libs, nil
}
