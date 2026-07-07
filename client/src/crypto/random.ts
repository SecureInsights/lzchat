export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0 || length > 1024 * 1024) {
    throw new Error("invalid random length");
  }
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}
