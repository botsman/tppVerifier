package main

import (
	"testing"
)

func TestParseOBID(t *testing.T) {
	tests := []struct {
		name             string
		entityNatRefCode string
		country          string
		authority        string
		want             string
		wantErr          bool
	}{
		{
			name:             "Malta example with spaces and dash",
			entityNatRefCode: "C 102960",
			country:          "MT",
			authority:        "MFSA",
			want:             "PSDMT-MFSA-C102960",
			wantErr:          false,
		},
		{
			name:             "Finland example with dash",
			entityNatRefCode: "29884997",
			country:          "FI",
			authority:        "FINFSA",
			want:             "PSDFI-FINFSA-29884997",
			wantErr:          false,
		},
		{
			name:             "With dash in nat ref code",
			entityNatRefCode: "0111027-9",
			country:          "FI",
			authority:        "FINFSA",
			want:             "PSDFI-FINFSA-01110279",
			wantErr:          false,
		},
		{
			name:             "With spaces and dashes",
			entityNatRefCode: "A B-C D-E F",
			country:          "DE",
			authority:        "BAFIN",
			want:             "PSDDE-BAFIN-ABCDEF",
			wantErr:          false,
		},
		{
			name:             "Empty nat ref code",
			entityNatRefCode: "",
			country:          "DE",
			authority:        "BAFIN",
			want:             "PSDDE-BAFIN-",
			wantErr:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOBID(tt.entityNatRefCode, tt.country, tt.authority)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOBID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseOBID() = %v, want %v", got, tt.want)
			}
		})
	}
}
