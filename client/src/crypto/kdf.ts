import { asBufferSource, concatBytes, numberToBytes, utf8 } from "./bytes";

function subtle(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is unavailable");
  }
  return globalThis.crypto.subtle;
}

export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const input = typeof data === "string" ? utf8(data) : data;
  return new Uint8Array(await subtle().digest("SHA-256", asBufferSource(input)));
}

export async function hmacSha256(key: Uint8Array, data: Uint8Array | string): Promise<Uint8Array> {
  const cryptoKey = await subtle().importKey("raw", asBufferSource(key), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign"
  ]);
  const input = typeof data === "string" ? utf8(data) : data;
  return new Uint8Array(await subtle().sign("HMAC", cryptoKey, asBufferSource(input)));
}

export async function hkdf(
  ikm: Uint8Array,
  info: string | Uint8Array,
  salt: Uint8Array | null,
  length = 32
): Promise<Uint8Array> {
  const cryptoKey = await subtle().importKey("raw", asBufferSource(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: asBufferSource(salt ?? new Uint8Array(32)),
      info: asBufferSource(typeof info === "string" ? utf8(info) : info)
    },
    cryptoKey,
    length * 8
  );
  return new Uint8Array(bits);
}

export async function pbkdf2Sha256(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
  length = 32
): Promise<Uint8Array> {
  if (iterations < 100_000 || iterations > 5_000_000) {
    throw new Error("unsafe pbkdf2 iterations");
  }
  const passKey = await subtle().importKey("raw", asBufferSource(utf8(passphrase)), "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle().deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: asBufferSource(salt),
      iterations
    },
    passKey,
    length * 8
  );
  return new Uint8Array(bits);
}

export function seqInfo(label: string, seq: number): Uint8Array {
  return concatBytes(utf8(label), numberToBytes(seq));
}
