package gemspec

import (
	"bufio"
	"io"
	"os"
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
	gemNameReg       = regexp.MustCompile(`(\.name)(\s|\t)*=(\s|\t)*('|")[a-zA-Z0-9_\-]*('|")`)
	gemVerReg        = regexp.MustCompile(`(\.version)(\s|\t)*=(\s|\t)*('|")[a-zA-Z0-9.]*('|")`)
	gemStrLic        = regexp.MustCompile(`(\.licenses)(\s|\t)*=(\s|\t)*\[.*\]`)
	packageNameRegEx = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)
	versionRegEx     = regexp.MustCompile(`^[a-zA-Z0-9.]+$`)
	fileNameVersion  = regexp.MustCompile(`^([\w_.\-]+)-([0-9.]+)$`)
)

func Parse(r io.Reader, filePath string) (types.Library, error) {
	var lib types.Library
	scanner := bufio.NewScanner(r)
	var gemName string
	var gemVersion string
	var licenses []string
	for scanner.Scan() {
		line := scanner.Text()
		// check if the file is binary or not, if binary return
		if !utf8.ValidString(line) {
			return lib, nil
		}
		quotesList := bwQuotes.FindStringSubmatch(line)
		if len(quotesList) > 1 {
			line = strings.TrimSpace(line)
			if gemName == "" && gemNameReg.MatchString(line) {
				gemName = quotesList[1]
			} else if gemVersion == "" && gemVerReg.MatchString(line) {
				gemVersion = quotesList[1]
			} else if gemStrLic.MatchString(line) {
				licenseList := bwQuotes.FindAllStringSubmatch(line, -1)
				for _, license := range licenseList {
					licenses = append(licenses, strings.Replace(license[1], " ", "", -1))
				}
				break
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return lib, xerrors.Errorf("scan error: %w", err)
	}

	// If still we did not find the name from file, if variable are refered in gemspec
	// try to take the name and version from gemspec file.
	// Else take name from previous directory
	dirPath, fileName := filepath.Split(filePath)
	if gemName == "" || gemVersion == "" {
		name, version := getInfoFromDir(strings.TrimSuffix(fileName, gemSpec))
		if name == "" || version == "" {
			// refer 1 more previous directory
			dirs := strings.Split(dirPath, string(os.PathSeparator))
			if len(dirs) >= 2 {
				name, version = getInfoFromDir(dirs[len(dirs)-2])
			}
		}
		if !(name == "" || version == "") {
			gemName = name
			gemVersion = version
		}
	}

	if gemName != "" && gemVersion != "" {
		lib = types.Library{
			Name:    gemName,
			Version: gemVersion,
			License: strings.Join(licenses, ","),
		}
	}
	return lib, nil
}

func getInfoFromDir(dir string) (gemName string, gemVersion string) {
	// parses dir names like /net-imap-0.1.1
	packageNameVersion := fileNameVersion.FindStringSubmatch(dir)
	if len(packageNameVersion) >= 3 {
		if packageNameRegEx.MatchString(packageNameVersion[1]) {
			gemName = packageNameVersion[1]
		}
		if versionRegEx.MatchString(packageNameVersion[2]) {
			gemVersion = packageNameVersion[2]
		}
	}
	return
}
