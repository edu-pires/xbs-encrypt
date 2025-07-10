# Mastercard Crypto Service

Node.js service to encrypt and decrypt Mastercard payloads.

## Endpoints

- `POST /encrypt`: Encrypts a JSON payload using Mastercard's public certificate.
- `POST /decrypt`: Decrypts a JWE using your private key from a .p12 file.

Deploy on https://render.com using `render.yaml`.
