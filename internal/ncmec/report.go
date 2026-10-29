// Package ncmec is a client for the NCMEC CyberTipline Reporting API used by
// electronic service providers (ESPs) to file reports under 18 U.S.C. § 2258A.
//
// API reference: https://report.cybertip.org/ispws/documentation/index.html
//
// Element ORDER matters: NCMEC validates against an XSD with xs:sequence
// elements. The order here follows the published documentation. Before going
// to production, download the live schema (GET /xsd with your credentials),
// save it as internal/ncmec/testdata/ncmec.xsd, and run the tests: they will
// validate generated XML against it when xmllint is available.
package ncmec

import (
	"encoding/xml"
	"time"
)

// Incident types accepted by <incidentType>.
const (
	IncidentChildPornography    = "Child Pornography (possession, manufacture, and distribution)"
	IncidentChildSexTrafficking = "Child Sex Trafficking"
	IncidentChildSexTourism     = "Child Sex Tourism"
	IncidentChildMolestation    = "Child Sexual Molestation"
	IncidentMisleadingDomain    = "Misleading Domain Name"
	IncidentMisleadingWords     = "Misleading Words or Digital Images on the Internet"
	IncidentOnlineEnticement    = "Online Enticement of Children for Sexual Acts"
	IncidentUnsolicitedObscene  = "Unsolicited Obscene Material Sent to a Child"
)

// Industry classification codes for <industryClassification>.
// A = prepubescent, B = pubescent; 1 = sex act, 2 = lascivious exhibition.
const (
	ClassA1 = "A1"
	ClassA2 = "A2"
	ClassB1 = "B1"
	ClassB2 = "B2"
)

// Time formats an ISO 8601 timestamp with timezone, as the API requires.
func Time(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Report is the <report> document sent to /submit.
type Report struct {
	XMLName              xml.Name              `xml:"report"`
	XSI                  string                `xml:"xmlns:xsi,attr,omitempty"`
	SchemaLocation       string                `xml:"xsi:noNamespaceSchemaLocation,attr,omitempty"`
	IncidentSummary      IncidentSummary       `xml:"incidentSummary"`
	InternetDetails      []InternetDetails     `xml:"internetDetails,omitempty"`
	Reporter             Reporter              `xml:"reporter"`
	PersonOrUserReported *PersonOrUserReported `xml:"personOrUserReported,omitempty"`
	AdditionalInfo       string                `xml:"additionalInfo,omitempty"`
}

// IncidentSummary is <incidentSummary>.
type IncidentSummary struct {
	IncidentType           string `xml:"incidentType"`
	Platform               string `xml:"platform,omitempty"`
	EscalateToHighPriority string `xml:"escalateToHighPriority,omitempty"`
	IncidentDateTime       string `xml:"incidentDateTime"`
	IncidentDateTimeDesc   string `xml:"incidentDateTimeDescription,omitempty"`
}

// InternetDetails wraps one incident location.
type InternetDetails struct {
	WebPageIncident *WebPageIncident `xml:"webPageIncident,omitempty"`
}

// WebPageIncident is <webPageIncident>.
type WebPageIncident struct {
	ThirdPartyHostedContent *bool    `xml:"thirdPartyHostedContent,attr,omitempty"`
	URLs                    []string `xml:"url,omitempty"`
	AdditionalInfo          string   `xml:"additionalInfo,omitempty"`
}

// Reporter is <reporter>.
type Reporter struct {
	ReportingPerson ReportingPerson `xml:"reportingPerson"`
	ContactPerson   *ContactPerson  `xml:"contactPerson,omitempty"`
}

// ReportingPerson is <reportingPerson>; Email is required.
type ReportingPerson struct {
	FirstName string `xml:"firstName,omitempty"`
	LastName  string `xml:"lastName,omitempty"`
	Email     string `xml:"email"`
}

// ContactPerson is <contactPerson>.
type ContactPerson struct {
	FirstName string `xml:"firstName,omitempty"`
	LastName  string `xml:"lastName,omitempty"`
	Email     string `xml:"email,omitempty"`
}

// PersonOrUserReported is <personOrUserReported>, the suspect account.
type PersonOrUserReported struct {
	ESPIdentifier   string           `xml:"espIdentifier,omitempty"`
	ESPService      string           `xml:"espService,omitempty"`
	IPCaptureEvents []IPCaptureEvent `xml:"ipCaptureEvent,omitempty"`
	AdditionalInfo  string           `xml:"additionalInfo,omitempty"`
}

// IPCaptureEvent is <ipCaptureEvent>. IPAddress is required and must be a
// valid IP. drop.i2p has no client IPs (I2P), so it does not send these.
type IPCaptureEvent struct {
	IPAddress     string `xml:"ipAddress"`
	EventName     string `xml:"eventName,omitempty"`
	DateTime      string `xml:"dateTime,omitempty"`
	PossibleProxy *bool  `xml:"possibleProxy,omitempty"`
	Port          int    `xml:"port,omitempty"`
}

// FileDetails is the <fileDetails> document sent to /fileinfo.
type FileDetails struct {
	XMLName                xml.Name         `xml:"fileDetails"`
	XSI                    string           `xml:"xmlns:xsi,attr,omitempty"`
	SchemaLocation         string           `xml:"xsi:noNamespaceSchemaLocation,attr,omitempty"`
	ReportID               string           `xml:"reportId"`
	FileID                 string           `xml:"fileId"`
	OriginalFileName       string           `xml:"originalFileName,omitempty"`
	UploadedToESPTimestamp string           `xml:"uploadedToEspTimestamp,omitempty"`
	LocationOfFile         string           `xml:"locationOfFile,omitempty"`
	FileViewedByESP        *bool            `xml:"fileViewedByEsp,omitempty"`
	ExifViewedByESP        *bool            `xml:"exifViewedByEsp,omitempty"`
	PubliclyAvailable      *bool            `xml:"publiclyAvailable,omitempty"`
	FileRelevance          string           `xml:"fileRelevance,omitempty"`
	FileAnnotations        *FileAnnotations `xml:"fileAnnotations,omitempty"`
	IndustryClassification string           `xml:"industryClassification,omitempty"`
	OriginalFileHashes     []FileHash       `xml:"originalFileHash,omitempty"`
	Details                []Details        `xml:"details,omitempty"`
	AdditionalInfo         []string         `xml:"additionalInfo,omitempty"`
}

// FileAnnotations holds empty marker elements; set a field to &struct{}{} to emit it.
type FileAnnotations struct {
	AnimeDrawingVirtualHentai *struct{} `xml:"animeDrawingVirtualHentai,omitempty"`
	PotentialMeme             *struct{} `xml:"potentialMeme,omitempty"`
	Viral                     *struct{} `xml:"viral,omitempty"`
	PossibleSelfProduction    *struct{} `xml:"possibleSelfProduction,omitempty"`
	PhysicalHarm              *struct{} `xml:"physicalHarm,omitempty"`
	ViolenceGore              *struct{} `xml:"violenceGore,omitempty"`
	Bestiality                *struct{} `xml:"bestiality,omitempty"`
	LiveStreaming             *struct{} `xml:"liveStreaming,omitempty"`
	Infant                    *struct{} `xml:"infant,omitempty"`
	GenerativeAI              *struct{} `xml:"generativeAi,omitempty"`
}

// FileHash is <originalFileHash hashType="...">.
type FileHash struct {
	HashType string `xml:"hashType,attr"`
	Value    string `xml:",chardata"`
}

// Details is a <details> block of name/value pairs (type EXIF or HASH).
type Details struct {
	Type  string          `xml:"type,attr,omitempty"`
	Pairs []NameValuePair `xml:"nameValuePair"`
}

// NameValuePair is <nameValuePair>; Name is at most 64 characters.
type NameValuePair struct {
	Name  string `xml:"name"`
	Value string `xml:"value"`
}

// Response is <reportResponse>.
type Response struct {
	XMLName             xml.Name `xml:"reportResponse"`
	ResponseCode        int      `xml:"responseCode"`
	ResponseDescription string   `xml:"responseDescription"`
	ReportID            string   `xml:"reportId"`
	FileID              string   `xml:"fileId"`
	Hash                string   `xml:"hash"`
}

// DoneResponse is <reportDoneResponse>, returned by /finish.
type DoneResponse struct {
	XMLName      xml.Name `xml:"reportDoneResponse"`
	ResponseCode int      `xml:"responseCode"`
	ReportID     string   `xml:"reportId"`
	FileIDs      []string `xml:"files>fileId"`
}

func boolPtr(b bool) *bool { return &b }
