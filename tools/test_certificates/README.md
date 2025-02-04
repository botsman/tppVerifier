A set of commands and configs to generate test certificates for the testing purposes.



1. Generate CA key
```bash
openssl genrsa -out ca.key 4096
```

2. Generate CA certificate
```bash
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/C=US/ST=CA/L=San Francisco/O=Test/OU=Test/CN=ca"
```

3. Generate private key:
```bash
openssl genrsa -out qseal.key 4096
```

4. Generate QcStatements separately:
```bash
go run generate_qc_statements.go main.go
```

5. Copy the output to the qseal.cnf file and replace the {raw_der_goes_here} placeholder.


6. Generate CSR:
```bash
openssl req -new -key qseal.key -out qseal.csr -config qseal.cnf
```

7. Generate self-signed certificate:
```bash
openssl x509 -req -days 365 -in qseal.csr -signkey qseal.key -out qseal.crt -extensions v3_ext -extfile qseal.cnf
```


8. Sign the certificate with CA:
```bash
openssl x509 -req -days 365 -in qseal.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out qseal.pem -extensions v3_ext -extfile qseal.cnf
```






openssl genrsa -out server.key 4096
openssl x509 -in qseal.pem -signkey server.key -x509toreq -copy_extensions copyall -out new_request.csr



To debug extensions structure:
openssl asn1parse -in qseal.crt -i


To try:
1. compare structures (original, new and specification)
2. extract raw der from original and add it to the new config




0.4.0.19495.1.1 PSP_AS
0.4.0.19495.1.2 PSP_PI
0.4.0.19495.1.3 PSP_AI
0.4.0.19495.1.4 PSP_IC
