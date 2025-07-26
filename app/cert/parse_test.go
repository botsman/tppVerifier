package cert

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// getTestDataPath returns the absolute path to a file or directory in testdata, relative to this test file.
func getTestDataPath(relPath string) string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata", relPath)
}


func TestGetCertFormat(t *testing.T) {
	certFormats := []struct {
		name   string
		format string
	}{
		{"PEM", "pem"},
		{"DER", "der"},
		{"PKCS7", "p7c"},
	}

	for _, format := range certFormats {
		t.Run(format.name, func(t *testing.T) {
			// Simulate getting the certificate format
			certPath := getTestDataPath("cert." + format.format)
			certContent, err := os.ReadFile(certPath)
			if err != nil {
				t.Fatalf("Couldn't read certificate file: %v\n", err)
			}
			got, err := GetCertFormat(certContent)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
			if got != certFormat(format.name) {
				t.Errorf("Expected %q, got %q", format.name, got)
			}
		})
	}
}
