import { asBufferSource } from "./bytes";

function subtle(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is unavailable");
  }
  return globalThis.crypto.subtle;
}

async function importAesKey(key: Uint8Array): Promise<CryptoKey> {
  if (key.length !== 32) {
    throw new Error("AES-GCM key must be 32 bytes");
  }
  return subtle().importKey("raw", asBufferSource(key), "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function aesGcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  if (nonce.length !== 12) {
    throw new Error("AES-GCM nonce must be 12 bytes");
  }
  const cryptoKey = await importAesKey(key);
  return new Uint8Array(
    await subtle().encrypt(
      { name: "AES-GCM", iv: asBufferSource(nonce), additionalData: asBufferSource(aad), tagLength: 128 },
      cryptoKey,
      asBufferSource(plaintext)
    )
  );
}

export async function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array
): Promise<Uint8Array> {
  if (nonce.length !== 12) {
    throw new Error("AES-GCM nonce must be 12 bytes");
  }
  const cryptoKey = await importAesKey(key);
  return new Uint8Array(
    await subtle().decrypt(
      { name: "AES-GCM", iv: asBufferSource(nonce), additionalData: asBufferSource(aad), tagLength: 128 },
      cryptoKey,
      asBufferSource(ciphertext)
    )
  );
}
