import { aesGcmDecrypt, aesGcmEncrypt } from "../crypto/aead";
import { base64urlDecode, base64urlEncode } from "../crypto/base64url";
import { fromUtf8, utf8, zeroize } from "../crypto/bytes";
import { stableJson } from "../crypto/stable-json";
import { deriveNonce, type SendRatchet, type ReceiveRatchet } from "../crypto/ratchet";
import { validatePlainPayload } from "./validator";
import type { PlainPayload, RelayAad, RelayEnvelope, RelayKind } from "./types";

export type SealInput = {
  roomId: string;
  from: string;
  to: string;
  kind: RelayKind;
  transcriptHash: string;
  ratchet: SendRatchet;
  payload: PlainPayload;
};

export async function sealPayload(input: SealInput): Promise<RelayEnvelope> {
  const step = await input.ratchet.next();
  const aadObject: RelayAad = {
    v: 3,
    t: "relay",
    roomId: input.roomId,
    from: input.from,
    to: input.to,
    kind: input.kind,
    seq: step.seq,
    transcriptHash: input.transcriptHash
  };
  const aad = utf8(stableJson(aadObject));
  const nonce = await deriveNonce(step.messageKey, input.kind, step.seq, aad);
  const plaintext = utf8(stableJson(input.payload));
  const ct = await aesGcmEncrypt(step.messageKey, nonce, aad, plaintext);
  zeroize(step.messageKey);
  return {
    v: 3,
    t: "relay",
    roomId: input.roomId,
    from: input.from,
    to: input.to,
    kind: input.kind,
    seq: step.seq,
    nonce: base64urlEncode(nonce),
    ct: base64urlEncode(ct)
  };
}

export async function openPayload(
  envelope: RelayEnvelope,
  transcriptHash: string,
  ratchet: ReceiveRatchet
): Promise<PlainPayload | null> {
  const key = await ratchet.messageKey(envelope.seq, envelope.kind);
  if (!key) {
    return null;
  }
  const aadObject: RelayAad = {
    v: 3,
    t: "relay",
    roomId: envelope.roomId,
    from: envelope.from,
    to: envelope.to,
    kind: envelope.kind,
    seq: envelope.seq,
    transcriptHash
  };
  const aad = utf8(stableJson(aadObject));
  let nonce: Uint8Array | null = null;
  let expectedNonce: Uint8Array | null = null;
  let plaintext: Uint8Array | null = null;
  try {
    nonce = base64urlDecode(envelope.nonce);
    expectedNonce = await deriveNonce(key, envelope.kind, envelope.seq, aad);
    if (base64urlEncode(nonce) !== base64urlEncode(expectedNonce)) {
      ratchet.restoreSkipped(envelope.seq, key);
      return null;
    }
    plaintext = await aesGcmDecrypt(key, nonce, aad, base64urlDecode(envelope.ct));
    ratchet.markAccepted(envelope.seq);
    return validatePlainPayload(JSON.parse(fromUtf8(plaintext)));
  } catch {
    ratchet.restoreSkipped(envelope.seq, key);
    return null;
  } finally {
    zeroize(key);
    if (nonce) {
      zeroize(nonce);
    }
    if (expectedNonce) {
      zeroize(expectedNonce);
    }
    if (plaintext) {
      zeroize(plaintext);
    }
  }
}
