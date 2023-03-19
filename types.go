package nvd

type NVDMeta struct {
	LastModifiedDate string
	Size             string
	ZipSize          string
	GzSize           string
	Sha256           string
}

// NVD CVE Feed JSON Schema:
// https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema
type CVEResults struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Format          string          `json:"format"`
	Version         string          `json:"version"`
	Timestamp       string          `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	Cve Cve `json:"cve"`
}

type Cve struct {
	ID                    string       `json:"id"`
	SourceIdentifier      string       `json:"sourceIdentifier,omitempty"`
	Published             string       `json:"published"`
	LastModified          string       `json:"lastModified"`
	VulnStatus            string       `json:"vulnStatus,omitempty"`
	EvaluatorComment      string       `json:"evaluatorComment,omitempty"`
	EvaluatorSolution     string       `json:"evaluatorSolution,omitempty"`
	EvaluatorImpact       string       `json:"evaluatorImpact,omitempty"`
	CisaExploitAdd        string       `json:"cisaExploitAdd,omitempty"`
	CisaActionDue         string       `json:"cisaActionDue,omitempty"`
	CisaRequiredAction    string       `json:"cisaRequiredAction,omitempty"`
	CisaVulnerabilityName string       `json:"cisaVulnerabilityName,omitempty"`
	Descriptions          []LangString `json:"descriptions"`
	References            []struct {
		URL    string   `json:"url"`
		Source string   `json:"source,omitempty"`
		Tags   []string `json:"tags,omitempty"`
	} `json:"references"`
	Metrics struct {
		CvssMetricV31 []struct {
			Source   string `json:"source"`
			Type     string `json:"type"`
			CvssData struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AttackVector          string  `json:"attackVector"`
				AttackComplexity      string  `json:"attackComplexity"`
				PrivilegesRequired    string  `json:"privilegesRequired"`
				UserInteraction       string  `json:"userInteraction"`
				Scope                 string  `json:"scope"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
				BaseSeverity          string  `json:"baseSeverity"`
			} `json:"cvssData"`
			ExploitabilityScore float64 `json:"exploitabilityScore"`
			ImpactScore         float64 `json:"impactScore"`
		} `json:"cvssMetricV31"`
		CvssMetricV2 []struct {
			Source   string `json:"source"`
			Type     string `json:"type"`
			CvssData struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AccessVector          string  `json:"accessVector"`
				AccessComplexity      string  `json:"accessComplexity"`
				Authentication        string  `json:"authentication"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
			} `json:"cvssData"`
			BaseSeverity            string  `json:"baseSeverity"`
			ExploitabilityScore     float64 `json:"exploitabilityScore"`
			ImpactScore             float64 `json:"impactScore"`
			AcInsufInfo             bool    `json:"acInsufInfo"`
			ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
			ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
			ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
			UserInteractionRequired bool    `json:"userInteractionRequired"`
		} `json:"cvssMetricV2"`
	} `json:"metrics,omitempty"`
	Weaknesses []struct {
		Source      string       `json:"source"`
		Type        string       `json:"type"`
		Description []LangString `json:"description"`
	} `json:"weaknesses,omitempty"`
	Configurations []struct {
		Operator string `json:"operator,omitempty"`
		Negate   string `json:"negate,omitempty"`
		Nodes    []struct {
			Operator string `json:"operator"`
			Negate   bool   `json:"negate,omitempty"`
			CpeMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				Criteria              string `json:"criteria"`
				MatchCriteriaID       string `json:"matchCriteriaId"`
				VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
				VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
				VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
				VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations,omitempty"`
	VendorComments []struct {
		Organization string `json:"organization"`
		Comment      string `json:"comment"`
		LastModified string `json:"lastModified"`
	} `json:"vendorComments,omitempty"`
}

type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type NVDFeed struct {
	CVEDataType         string    `json:"CVE_data_type"`
	CVEDataFormat       string    `json:"CVE_data_format"`
	CVEDataVersion      string    `json:"CVE_data_version"`
	CVEDataNumberOfCVEs string    `json:"CVE_data_numberOfCVEs"`
	CVEDataTimestamp    string    `json:"CVE_data_timestamp"`
	CVEItems            []CVEItem `json:"CVE_Items"`
}

type CVEItem struct {
	CVE struct {
		DataType    string `json:"data_type"`
		DataFormat  string `json:"data_format"`
		DataVersion string `json:"data_version"`
		CVEDataMeta struct {
			ID       string `json:"ID"`
			ASSIGNER string `json:"ASSIGNER"`
		} `json:"CVE_data_meta"`
		Problemtype struct {
			ProblemtypeData []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"problemtype_data"`
		} `json:"problemtype"`
		References struct {
			ReferenceData []struct {
				URL       string   `json:"url"`
				Name      string   `json:"name"`
				Refsource string   `json:"refsource"`
				Tags      []string `json:"tags"`
			} `json:"reference_data"`
		} `json:"references"`
		Description struct {
			DescriptionData []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
	} `json:"cve"`
	Configurations struct {
		CVEDataVersion string `json:"CVE_data_version"`
		Nodes          []struct {
			Operator string `json:"operator"`
			CPEMatch []struct {
				Vulnerable bool   `json:"vulnerable"`
				CPE23URI   string `json:"cpe23Uri"`
			} `json:"cpe_match"`
		} `json:"nodes"`
	} `json:"configurations"`
	Impact struct {
		BaseMetricV3 struct {
			CvssV3 struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AttackVector          string  `json:"attackVector"`
				AttackComplexity      string  `json:"attackComplexity"`
				PrivilegesRequired    string  `json:"privilegesRequired"`
				UserInteraction       string  `json:"userInteraction"`
				Scope                 string  `json:"scope"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
				BaseSeverity          string  `json:"baseSeverity"`
			} `json:"cvssV3"`
			ExploitabilityScore float64 `json:"exploitabilityScore"`
			ImpactScore         float64 `json:"impactScore"`
		} `json:"baseMetricV3"`
		BaseMetricV2 struct {
			CvssV2 struct {
				Version               string  `json:"version"`
				VectorString          string  `json:"vectorString"`
				AccessVector          string  `json:"accessVector"`
				AccessComplexity      string  `json:"accessComplexity"`
				Authentication        string  `json:"authentication"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
			} `json:"cvssV2"`
			Severity                string  `json:"severity"`
			ExploitabilityScore     float64 `json:"exploitabilityScore"`
			ImpactScore             float64 `json:"impactScore"`
			AcInsufInfo             bool    `json:"acInsufInfo"`
			ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
			ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
			ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
			UserInteractionRequired bool    `json:"userInteractionRequired"`
		} `json:"baseMetricV2"`
	} `json:"impact"`
	PublishedDate    string `json:"publishedDate"`
	LastModifiedDate string `json:"lastModifiedDate"`
	Reserved         bool   `json:"reserved,omitempty"`
}

type Vendor struct {
	Name     string
	Products []Product
}

type Product struct {
	Name     string
	URIShort string
}

// WeaknessCatalog has CWE items
type WeaknessCatalog struct {
	Weaknesses []Weakness         `xml:"Weaknesses>Weakness"`
	Categories []WeaknessCategory `xml:"Categories>Category"`
}

type Weakness struct {
	ID          string `xml:"ID,attr"`
	Name        string `xml:"Name,attr"`
	Description string `xml:"Description"`
	// ExtendedDescription string `xml:"Extended_Description"`
}

type WeaknessCategory struct {
	ID          string `xml:"ID,attr"`
	Name        string `xml:"Name,attr"`
	Description string `xml:"Summary"`
}

type CPEMatchFeed struct {
	CPEMatches []CPEMatch `json:"matches"`
}

type CPEMatch struct {
	CPE23URI string `json:"cpe23Uri"`
}
