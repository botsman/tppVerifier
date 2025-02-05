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

5. Copy the output to the qseal.cnf file and replace the value for 1.3.6.1.5.5.7.1.3 policy.


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
