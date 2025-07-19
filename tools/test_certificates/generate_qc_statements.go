package main

import (
	"encoding/asn1"
	"log"
    "github.com/botsman/tppVerifier/app/verify"
    "github.com/botsman/tppVerifier/app/cert"
)


func encodeQcStatements() ([]byte, error) {
    qcStatements := []cert.QCStatement{
        {
            ID: asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 1},
            Value: asn1.RawValue{
                IsCompound: false,
            },
        },
        {
            ID: asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 3},
            Value: asn1.RawValue{
                Tag: asn1.TagInteger,
                IsCompound: false,
                Bytes: []byte{10},
            },
        },
        {
            ID: asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 5},
            Value: asn1.RawValue{
                FullBytes: mustEncodeASN1([]verify.URLStruct{
                    {URL: "https://example.com/qcps_en", Lang: "en"},
                    {URL: "https://example.com/qcps_hu", Lang: "hu"},
                }),
            },
        },
        {
            ID: asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6},
            Value: asn1.RawValue{
                Tag: asn1.TagSequence,
                IsCompound: true,
                Bytes: []byte{6, 7, 4, 0, 142, 70, 1, 6, 2},
            },
        },
        {
            ID: asn1.ObjectIdentifier{0, 4, 0, 19495, 2},
            Value: asn1.RawValue{
                FullBytes: mustEncodeASN1(cert.PSD2QcType{
                    RolesOfPSP: []cert.Role{
                        {OID: asn1.ObjectIdentifier{0, 4, 0, 19495, 1, 1}, Value: "PSP_PI"},
                        {OID: asn1.ObjectIdentifier{0, 4, 0, 19495, 1, 2}, Value: "PSP_AI"},
                    },
                    NCAName: "Finnish Financial Supervisory Authority",
                    NCAId:   "FI-FINFSA",
                }),
            },
        },
    }

    encoded, err := asn1.Marshal(qcStatements)
    if err != nil {
        log.Fatalf("Failed to encode QC Statements: %v", err)
        return nil, err
    }

    return encoded, nil
}

func mustEncodeASN1(value interface{}) []byte {
    encoded, err := asn1.Marshal(value)
    if err != nil {
        panic(err)
    }
    return encoded
}

// Helper function to encode an OID into ASN.1 format
func mustEncodeOID(oid string) []byte {
	encoded, err := asn1.Marshal(asn1.ObjectIdentifier(parseOID(oid)))
	if err != nil {
		panic(err)
	}
	return encoded
}

// Helper function to parse an OID string into a slice of integers
func parseOID(oid string) []int {
	var result []int
	var num int
	for _, c := range oid {
		if c == '.' {
			result = append(result, num)
			num = 0
		} else {
			num = num*10 + int(c-'0')
		}
	}
	result = append(result, num)
	return result
}
