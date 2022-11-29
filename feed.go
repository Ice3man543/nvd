package nvd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strconv"
)

const (
	nvdDataFeeds     = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.json.gz"
	nvdDataFeedsMeta = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%s.meta"
	nvdCPEMatchFeed  = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz"
)

// ErrNotFound occurs when CVE is expected but no result is returned from fetch operations
var ErrNotFound = errors.New("CVE not found")

// FetchCVE extracts the year of a CVE ID, and returns a CVEItem data struct
// from the most up-to-date NVD data feed for that year
func (c *Client) FetchCVE(cveID string) (CVEItem, error) {
	if !IsCVEIDStrict(cveID) {
		return CVEItem{}, fmt.Errorf("invalid CVE ID: %s", cveID)
	}

	// TODO validate required data struct values before return

	cve, err := c.fetchNVDCVE(cveID)
	switch err {
	case nil:
		// Found cve in NVD feed, return result
		return cve, nil
	case ErrNotFound:
		// If not found in NVD feeds, fall back to check MITRE database
		// see if valid CVE ID exists with Reserved status
		cve, err = fetchReservedCVE(cveID)
		if err != nil {
			return CVEItem{}, ErrNotFound
		}
		return cve, nil
	default:
		// Case err != nil
		return CVEItem{}, err
	}
}

// FetchUpdatedCVEs returns a slice of most recently published and modified CVES
// from the previous eight days. This feed is updated approximately every two hours by NVD.
// NVD recommends that the "modified" feed should be used to keep up-to-date.
func (c *Client) FetchUpdatedCVEs() ([]CVEItem, error) {
	feedName := "modified"
	err := c.updateFeed(feedName)
	if err != nil {
		return nil, err
	}

	raw, err := c.loadFeed(feedName)
	if err != nil {
		return nil, err
	}

	var nvd NVDFeed
	err = json.Unmarshal(raw, &nvd)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling modified feed: %v", err)
	}
	return nvd.CVEItems, nil
}

func (c *Client) updateFeed(year string) error {
	err := c.downloadFeed(
		fmt.Sprintf(nvdDataFeeds, year),
		c.pathToFeed(year),
	)
	if err != nil {
		return fmt.Errorf("error fetching %s remote feed: %v", year, err)
	}
	return nil
}

func (c *Client) fetchNVDCVE(cveID string) (cve CVEItem, err error) {
	yi, _ := ParseCVEID(cveID)
	year := strconv.Itoa(yi)

	// Update feed if local database doesn't exist yet.
	if _, err := os.Stat(c.pathToFeed(year)); os.IsNotExist(err) {
		err = c.updateFeed(year)
		if err != nil {
			return CVEItem{}, err
		}
	}

	cve, err = c.searchFeed(year, cveID)
	if err != nil {
		if err == ErrNotFound {
			// pass ErrNotFound through to caller function
			return CVEItem{}, err
		}
		return CVEItem{}, fmt.Errorf("error fetching %s local feed: %v", year, err)
	}
	return cve, nil
}

func (c *Client) pathToFeed(year string) string {
	return path.Join(c.feedDir, fmt.Sprintf("%s.json", year))
}

func (c *Client) loadFeed(year string) ([]byte, error) {
	p := c.pathToFeed(year)
	raw, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("error reading local feed file %s: %v", p, err)
	}
	return raw, nil
}

func (c *Client) searchFeed(year string, cveID string) (CVEItem, error) {
	p := c.pathToFeed(year)
	f, err := os.Open(p)
	if err != nil {
		return CVEItem{}, err
	}
	defer f.Close()

	decoder := json.NewDecoder(f)

	// Discard JSON tokens until reaching CVE_Items array
	for {
		tok, err := decoder.Token()
		if err != nil {
			return CVEItem{}, err
		}
		if tok == "CVE_Items" {
			// Read next opening bracket
			_, _ = decoder.Token()
			break
		}
	}

	for decoder.More() {
		var cve CVEItem

		err = decoder.Decode(&cve)
		if err != nil {
			return CVEItem{}, err
		}

		if cve.CVE.CVEDataMeta.ID == cveID {
			return cve, nil
		}
	}

	return CVEItem{}, ErrNotFound
}

// downloadFeed downloads a gz compressed feed file from u url to p file path
func (c *Client) downloadFeed(u, p string) (err error) {
	resp, err := http.Get(u)
	if err != nil {
		return fmt.Errorf("error http request to %s: %v", u, err)
	}
	if resp.Body == nil {
		return fmt.Errorf("no response body for %s", u)
	}
	defer resp.Body.Close()

	raw, err := decompressGZ(resp.Body)
	if err != nil {
		return fmt.Errorf("could not decompress response to %s: %v", u, err)
	}

	file, err := os.Create(p)
	if err != nil {
		return fmt.Errorf("error creating local feed file %s: %v", p, err)
	}
	defer file.Close()

	_, err = file.Write(raw)
	if err != nil {
		return fmt.Errorf("error writing to local feed file %s: %v", p, err)
	}
	return nil
}
