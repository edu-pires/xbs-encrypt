import { CompactEncrypt, compactDecrypt, importX509, importPKCS8 } from 'jose';

export async function importPrivateKeyFromBase64(base64Pem) {
  const pem = Buffer.from(base64Pem, 'base64').toString('utf-8');
  return await importPKCS8(pem, 'RSA-OAEP-256');
}

export async function encryptPayload(payload, certPem, kid) {
  const payloadStr = JSON.stringify(payload);
  const publicKey = await importX509(certPem, 'RSA-OAEP-256');

  const jwe = await new CompactEncrypt(new TextEncoder().encode(payloadStr))
    .setProtectedHeader({
      alg: 'RSA-OAEP-256',
      enc: 'A256GCM',
      cty: 'application/json',
      kid: kid
    })
    .encrypt(publicKey);

  return jwe;
}

export async function decryptPayload(jwe, privateKeyBase64) {
  const privateKey = await importPrivateKeyFromBase64(privateKeyBase64);
  const { plaintext } = await compactDecrypt(jwe, privateKey);
  return new TextDecoder().decode(plaintext);
}
