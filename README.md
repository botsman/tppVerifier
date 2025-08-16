# tppVerifier
Open Banking TPP verifier API description

# How it works
This project implements a verification service for Open Banking Third Party Providers (TPPs). 
It verifies TPP certificates by:
- Parsing and validating the certificate.
- Checking the certificate against a Certificate Authority (CA) bundle.
- Performing certificate revocation checks.
- Verifying TPPs against EBA (European Banking Authority) registry.

# Example response
```json
{
    "cert": { // parsed certificate data
        "registers": null,
        "created_at": "0001-01-01T00:00:00Z",
        "updated_at": "0001-01-01T00:00:00Z",
        "is_active": false,
    },
    "tpp": { // parsed TPP data
        "NameLatin": "Suomen Asiakastieto Oy",
        "NameNative": "Suomen Asiakastieto Oy",
        "Id": "FI_FIN_FSA!01110279",
        "OBID": "PSDFI-FINFSA-01110279",
        "Authority": "FINFSA",
        "Country": "FI",
        "Services": {
            "FI": [
                "AIS"
            ],
            "SE": [
                "AIS"
            ]
        },
        "AuthorizedAt": "2019-10-02T00:00:00Z",
        "WithdrawnAt": null,
        "Type": "PSD_AISP",
        "CreatedAt": "2025-08-05T18:34:38.283Z",
        "UpdatedAt": "2025-08-05T18:34:38.283Z",
        "Registry": "EBA"
    },
    "valid": true,
    "scopes": { // intersection of TPP services and certificate scopes
        "FI": [
            "AIS"
        ],
        "SE": [
            "AIS"
        ]
    }
}
```

# Deployment
Deployment consists of running the main server, which does all the verification work, and a database to store the results.

The database is used to store a list of trusted certificates and TPPs.
The database needs to be initialized with the CA bundle and EBA registry data. The tools provided in the `tools` directory can be used to populate the database:
- `tools/eba_certs`: Downloads a list of trusted root certificates from the EBA registry and stores them in the database.
- `tools/eba_tpps`: Downloads a list of TPPs from the EBA registry and stores them in the database.

Both `eba_certs` and `eba_tpps` scripts need to be run daily in order to contains the up-to-date state.

# Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
