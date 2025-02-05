package main

import (
	"encoding/asn1"
	"strings"
	"fmt"
	"log"
	"github.com/botsman/tppVerifier/app/verify"
)

func parseQcStatements(data []byte) error {
	// Parse ASN.1 Sequence
	var qcStatements []verify.QCStatement
	_, err := asn1.Unmarshal(data, &qcStatements)
	if err != nil {
		log.Fatalf("Failed to unmarshal ASN.1: %v", err)
	}

	for _, stmt := range qcStatements {
		switch {
		case stmt.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}):
			var urlStructs []verify.URLStruct
			_, err := asn1.Unmarshal(stmt.Value.FullBytes, &urlStructs)
			if err != nil {
				fmt.Println(err)
			}
			for _, urlStruct := range urlStructs {
				fmt.Println(urlStruct.URL, urlStruct.Lang)
			}
		case stmt.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 19495, 2}):
			var psd2 verify.PSD2QcType
			_, err := asn1.Unmarshal(stmt.Value.FullBytes, &psd2)
			if err != nil {
				fmt.Println(err)
			}
			for _, role := range psd2.RolesOfPSP {
				fmt.Println(role.OID, role.Value)
			}
			fmt.Println(psd2.NCAName, psd2.NCAId)
		}
	}
	return nil
}

func main() {
	// certPath := "/path/to/file"
	// certFile, err := os.Open(certPath)
	// if err != nil {
	// 	panic(err)
	// }
	// defer certFile.Close()

	// rest, err := io.ReadAll(certFile)
	// block, rest := pem.Decode(rest)
	// cert, err := x509.ParseCertificate(block.Bytes)
	// if err != nil {
	// 	panic(err)
	// }
	// for _, ext := range cert.Extensions {
	// 	if ext.Id.Equal([]int{1, 3, 6, 1, 5, 5, 7, 1, 3}) {
	// 		parseQcStatements(ext.Value)
	// 	}
	// }
	val, err := encodeQcStatements()
	if err != nil {
		log.Fatalf("Failed to encode QC Statements: %v", err)
	}
	// parseQcStatements(val)
	hexVal := fmt.Sprintf("%x", val)
	fmt.Println(strings.ToUpper(hexVal))
}
