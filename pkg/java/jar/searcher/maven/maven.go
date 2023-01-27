package maven

import (
	"encoding/json"
	"fmt"
	jtypes "github.com/aquasecurity/go-dep-parser/pkg/java/jar/types"
	"golang.org/x/xerrors"
	"net/http"
	"sort"
)

const (
	idQuery         = `g:"%s" AND a:"%s"`
	artifactIdQuery = `a:"%s" AND p:"jar"`
	sha1Query       = `1:"%s"`
)

type apiResponse struct {
	Response struct {
		NumFound int `json:"numFound"`
		Docs     []struct {
			ID           string `json:"id"`
			GroupID      string `json:"g"`
			ArtifactID   string `json:"a"`
			Version      string `json:"v"`
			P            string `json:"p"`
			VersionCount int    `json:versionCount`
		} `json:"docs"`
	} `json:"response"`
}

type Searcher struct {
	baseURL    string
	httpClient *http.Client
}

func NewSearcher(baseURL string, httpClient *http.Client) Searcher {
	return Searcher{
		baseURL:    baseURL,
		httpClient: httpClient,
	}
}

func (s Searcher) Exists(groupID, artifactID string) (bool, error) {
	req, err := http.NewRequest(http.MethodGet, s.baseURL, nil)
	if err != nil {
		return false, xerrors.Errorf("unable to initialize HTTP client: %w", err)
	}

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf(idQuery, groupID, artifactID))
	q.Set("rows", "1")
	req.URL.RawQuery = q.Encode()

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false, xerrors.Errorf("http error: %w", err)
	}
	defer resp.Body.Close()

	var res apiResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false, xerrors.Errorf("json decode error: %w", err)
	}
	return res.Response.NumFound > 0, nil
}

func (s Searcher) SearchBySHA1(sha1 string) (jtypes.Properties, error) {

	req, err := http.NewRequest(http.MethodGet, s.baseURL, nil)
	if err != nil {
		return jtypes.Properties{}, xerrors.Errorf("unable to initialize HTTP client: %w", err)
	}

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf(sha1Query, sha1))
	q.Set("rows", "1")
	q.Set("wt", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return jtypes.Properties{}, xerrors.Errorf("sha1 search error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return jtypes.Properties{}, xerrors.Errorf("status %s from %s", resp.Status, req.URL.String())
	}

	var res apiResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return jtypes.Properties{}, xerrors.Errorf("json decode error: %w", err)
	}

	if len(res.Response.Docs) == 0 {
		return jtypes.Properties{}, xerrors.Errorf("digest %s: %w", sha1, jtypes.ArtifactNotFoundErr)
	}

	// Some artifacts might have the same SHA-1 digests.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	docs := res.Response.Docs
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].ID < docs[j].ID
	})
	d := docs[0]

	return jtypes.Properties{
		GroupID:    d.GroupID,
		ArtifactID: d.ArtifactID,
		Version:    d.Version,
	}, nil
}

func (s Searcher) SearchByArtifactID(artifactID string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, s.baseURL, nil)
	if err != nil {
		return "", xerrors.Errorf("unable to initialize HTTP client: %w", err)
	}

	q := req.URL.Query()
	q.Set("q", fmt.Sprintf(artifactIdQuery, artifactID))
	q.Set("rows", "20")
	q.Set("wt", "json")
	req.URL.RawQuery = q.Encode()

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", xerrors.Errorf("artifactID search error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", xerrors.Errorf("status %s from %s", resp.Status, req.URL.String())
	}

	var res apiResponse
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", xerrors.Errorf("json decode error: %w", err)
	}

	if len(res.Response.Docs) == 0 {
		return "", xerrors.Errorf("artifactID %s: %w", artifactID, jtypes.ArtifactNotFoundErr)
	}

	// Some artifacts might have the same artifactId.
	// e.g. "javax.servlet:jstl" and "jstl:jstl"
	docs := res.Response.Docs
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].VersionCount > docs[j].VersionCount
	})
	d := docs[0]

	return d.GroupID, nil
}
