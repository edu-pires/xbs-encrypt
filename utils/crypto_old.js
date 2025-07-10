import fs from 'fs';
import { CompactEncrypt, compactDecrypt, importX509, importPKCS8 } from 'jose';
import forge from 'node-forge';

export async function extractPrivateKeyFromP12(p12Path, password) {
  const p12Buffer = fs.readFileSync(p12Path);
  const p12Der = forge.util.createBuffer(p12Buffer.toString('binary'));
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, password);

  const keyBags = p12.getBags({ bagType: forge.pki.oids.keyBag });
  const pkcs8Bags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });

  const bag = keyBags[forge.pki.oids.keyBag]?.[0] || pkcs8Bags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0];
  if (!bag || !bag.key) {
    throw new Error('Private key not found in the .p12 file.');
  }

  const pkcs8Asn1 = forge.pki.wrapRsaPrivateKey(forge.pki.privateKeyToAsn1(bag.key));
  const pkcs8Pem = forge.pki.privateKeyInfoToPem(pkcs8Asn1);

  return pkcs8Pem;
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

export async function decryptPayload(jwe, privateKeyPath, password) {
  const privateKeyPem = await extractPrivateKeyFromP12(privateKeyPath, password);
  const privateKey = await importPKCS8(privateKeyPem, 'RSA-OAEP-256');

  const { plaintext } = await compactDecrypt(jwe, privateKey);
  const decrypted = new TextDecoder().decode(plaintext);

  return decrypted;
}
