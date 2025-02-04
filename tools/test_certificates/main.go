package main

import (
	// "crypto/x509"
	"encoding/asn1"
	"strings"
	// "encoding/pem"
	"fmt"
	// "io"
	"log"
	// "os"
)

type QCStatement struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"optional"`
}

type Role struct {
	OID   asn1.ObjectIdentifier
	Value string
}

type PSD2QcType struct {
	RolesOfPSP []Role
	NCAName    string
	NCAId      string
}

type URLStruct struct {
	URL  string
	Lang string
}

func parseQcStatements(data []byte) error {
	// Parse ASN.1 Sequence
	var qcStatements []QCStatement
	_, err := asn1.Unmarshal(data, &qcStatements)
	if err != nil {
		log.Fatalf("Failed to unmarshal ASN.1: %v", err)
	}

	for _, stmt := range qcStatements {
		fmt.Println(stmt.ID, stmt.Value)
		// switch {
		// case stmt.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5}):
		// 	var urlStructs []URLStruct
		// 	_, err := asn1.Unmarshal(stmt.Value.FullBytes, &urlStructs)
		// 	if err != nil {
		// 		fmt.Println(err)
		// 	}
		// 	for _, urlStruct := range urlStructs {
		// 		fmt.Println(urlStruct.URL, urlStruct.Lang)
		// 	}
		// case stmt.ID.Equal(asn1.ObjectIdentifier{0, 4, 0, 19495, 2}):
		// 	var psd2 PSD2QcType
		// 	_, err := asn1.Unmarshal(stmt.Value.FullBytes, &psd2)
		// 	if err != nil {
		// 		fmt.Println(err)
		// 	}
		// 	for _, role := range psd2.RolesOfPSP {
		// 		fmt.Println(role.OID, role.Value)
		// 	}
		// 	fmt.Println(psd2.NCAName, psd2.NCAId)
		// }
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
