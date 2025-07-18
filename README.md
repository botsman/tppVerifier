# tppVerifier
Open Banking TPP verified API description

# How it works
This project implements a verification service for Open Banking Third Party Providers (TPPs). 
It verifies TPP certificates by:
- Parsing and validating the certificate.
- Checking the certificate against a Certificate Authority (CA) bundle.
- Performing certificate revocation checks.
- Verifying TPPs against EBA (European Banking Authority) registry.

# Deployment
Deployment consists of running the main server, which does all the verification work, and a database to store the results.

TODO: add instructions for deploying the server and database.

The database is used to store a list of trusted certificates and TPPs.
The database needs to be initialized with the CA bundle and EBA registry data. The tools provided in the `tools` directory can be used to populate the database:
- `tools/eba_certs`: Downloads a list of trusted root certificates from the EBA registry and stores them in the database.
- `tools/eba_tpps`: Downloads a list of TPPs from the EBA registry and stores them in the database.

# Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
