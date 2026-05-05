# RSA-4096 Keys

Place the following files in this directory:
- `private_key.pem` — RSA-4096 private key (PKCS#8 format)
- `public_key.pem`  — RSA-4096 public key (X.509 SubjectPublicKeyInfo format)

## Generation

```bash
# Generate RSA-4096 private key (PKCS#8)
openssl genrsa -out private_key_raw.pem 4096
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt \
  -in private_key_raw.pem -out private_key.pem

# Extract the public key
openssl rsa -in private_key_raw.pem -pubout -out public_key.pem

# Remove the intermediate file
rm private_key_raw.pem
```

## Security

- `private_key.pem` is listed in `.gitignore` — NEVER commit it
- The public key (`public_key.pem`) is shared with the Node.js agent at registration time
- The server returns the public key via `POST /api/v1/agents/register`
