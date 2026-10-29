package ncmec

import (
	"fmt"
	"time"
)

// SchemaLocation is referenced from generated documents.
const SchemaLocation = "https://report.cybertip.org/ispws/xsd"

// ReporterInfo identifies the ESP staff member filing reports.
type ReporterInfo struct {
	FirstName, LastName, Email string
	Platform                   string // e.g. "drop.i2p"
	Service                    string // e.g. "drop.i2p file hosting"
}

// FileIncident is one stored file being reported.
type FileIncident struct {
	FileID           string
	PublicURL        string // URL where the file was available
	OriginalFilename string
	UploadTime       time.Time
	UploaderID       string // I2P destination (b32) of the uploader, if known
	SHA256           string
	PerceptualHash   string
	ViewedByESP      bool   // true only if a person at the ESP looked at the file
	Classification   string // optional: ClassA1..ClassB2, only if a reviewer assessed it
	Notes            string // free-text context from the reviewer
}

// BuildFileReport creates the report and file details for one incident.
func BuildFileReport(rep ReporterInfo, inc FileIncident) (*Report, FileToReport) {
	r := &Report{
		XSI:            "http://www.w3.org/2001/XMLSchema-instance",
		SchemaLocation: SchemaLocation,
		IncidentSummary: IncidentSummary{
			IncidentType:         IncidentChildPornography,
			Platform:             rep.Platform,
			IncidentDateTime:     Time(inc.UploadTime),
			IncidentDateTimeDesc: "Time the file was uploaded to the service.",
		},
		Reporter: Reporter{ReportingPerson: ReportingPerson{
			FirstName: rep.FirstName, LastName: rep.LastName, Email: rep.Email,
		}},
	}
	if inc.PublicURL != "" {
		r.InternetDetails = []InternetDetails{{WebPageIncident: &WebPageIncident{URLs: []string{inc.PublicURL}}}}
	}
	if inc.UploaderID != "" {
		r.PersonOrUserReported = &PersonOrUserReported{
			ESPIdentifier: inc.UploaderID,
			ESPService:    rep.Service,
			AdditionalInfo: "The uploader connected through the I2P anonymity network. " +
				"The identifier is the uploader's I2P destination (b32 address). " +
				"No IP address is available to the service.",
		}
	}
	r.AdditionalInfo = fmt.Sprintf("File hosted on %s, an I2P service. File ID %s. "+
		"The file was removed from public access when this report was filed.", rep.Platform, inc.FileID)

	d := FileDetails{
		XSI:                    "http://www.w3.org/2001/XMLSchema-instance",
		SchemaLocation:         SchemaLocation,
		OriginalFileName:       inc.OriginalFilename,
		UploadedToESPTimestamp: Time(inc.UploadTime),
		FileViewedByESP:        boolPtr(inc.ViewedByESP),
		PubliclyAvailable:      boolPtr(true),
		FileRelevance:          "Reported",
	}
	if inc.ViewedByESP && inc.Classification != "" {
		d.IndustryClassification = inc.Classification
	}
	if inc.SHA256 != "" {
		d.OriginalFileHashes = append(d.OriginalFileHashes, FileHash{HashType: "SHA256", Value: inc.SHA256})
	}
	if inc.PerceptualHash != "" {
		d.Details = append(d.Details, Details{Type: "HASH", Pairs: []NameValuePair{{Name: "dHash64", Value: inc.PerceptualHash}}})
	}
	if inc.Notes != "" {
		d.AdditionalInfo = append(d.AdditionalInfo, inc.Notes)
	}
	return r, FileToReport{Filename: inc.OriginalFilename, Details: d}
}
