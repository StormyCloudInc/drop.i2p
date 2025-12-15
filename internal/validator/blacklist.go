package validator

import (
	"path/filepath"
	"strings"
)

// BlockedExtensions contains file extensions that are not allowed
var BlockedExtensions = map[string]bool{
	// Windows executables
	".exe": true, ".bat": true, ".cmd": true, ".com": true,
	".scr": true, ".pif": true, ".msi": true, ".dll": true,

	// Script files
	".vbs": true, ".vbe": true, ".js": true, ".jse": true,
	".ws": true, ".wsf": true, ".wsc": true, ".wsh": true,

	// PowerShell
	".ps1": true, ".ps2": true, ".psc1": true, ".psc2": true,
	".psm1": true, ".psd1": true,

	// Other dangerous types
	".msc": true, ".msp": true, ".reg": true, ".inf": true,
	".scf": true, ".lnk": true, ".hta": true, ".cpl": true,
}

// DangerousMimeTypes contains MIME types that indicate potentially harmful content
var DangerousMimeTypes = map[string]bool{
	"application/x-executable":     true,
	"application/x-dosexec":        true,
	"application/x-msdownload":     true,
	"application/x-msdos-program":  true,
	"application/x-ms-installer":   true,
	"application/x-shellscript":    true,
	"application/x-batch":          true,
	"application/x-msi":            true,
}

// IsAllowedExtension checks if a filename has an allowed extension
func IsAllowedExtension(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		// Files without extensions are allowed
		return true
	}
	return !BlockedExtensions[ext]
}

// IsAllowedMimeType checks if a MIME type is allowed
func IsAllowedMimeType(mimeType string) bool {
	// Normalize MIME type (remove charset, etc.)
	mimeType = strings.ToLower(strings.Split(mimeType, ";")[0])
	mimeType = strings.TrimSpace(mimeType)
	return !DangerousMimeTypes[mimeType]
}

// ValidateFile performs all validation checks on a file
func ValidateFile(filename, mimeType string) (bool, string) {
	// Check extension
	if !IsAllowedExtension(filename) {
		ext := strings.ToLower(filepath.Ext(filename))
		return false, "File extension " + ext + " is not allowed"
	}

	// Check MIME type
	if !IsAllowedMimeType(mimeType) {
		return false, "File type " + mimeType + " is not allowed"
	}

	return true, ""
}

// AddBlockedExtension adds a new extension to the blacklist
func AddBlockedExtension(ext string) {
	ext = strings.ToLower(ext)
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	BlockedExtensions[ext] = true
}

// RemoveBlockedExtension removes an extension from the blacklist
func RemoveBlockedExtension(ext string) {
	ext = strings.ToLower(ext)
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	delete(BlockedExtensions, ext)
}
