import { base64urlDecode, base64urlEncode } from "./base64url";
import { asBufferSource, concatBytes, utf8 } from "./bytes";
import { hkdf, sha256 } from "./kdf";
import { stableJson } from "./stable-json";
import type { CapabilitySet } from "../protocol/types";

export type SessionKeys = {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyBytes: Uint8Array;
  publicKeyToken: string;
};

export type PairSession = {
  peerClientId: string;
  transcriptHash: string;
  rootKey: Uint8Array;
  sendCK: Uint8Array;
  recvCK: Uint8Array;
  mediaSendCK: Uint8Array;
  mediaRecvCK: Uint8Array;
};

function subtle(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto is unavailable");
  }
  return globalThis.crypto.subtle;
}

export async function generateSessionKeys(): Promise<SessionKeys> {
  const keyPair = await subtle().generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const publicKeyBytes = new Uint8Array(await subtle().exportKey("raw", keyPair.publicKey));
  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicKeyBytes,
    publicKeyToken: base64urlEncode(publicKeyBytes)
  };
}

export async function importPeerPublicKey(sessionPub: string): Promise<CryptoKey> {
  const raw = base64urlDecode(sessionPub);
  if (raw.length !== 65 || raw[0] !== 4) {
    throw new Error("invalid P-256 public key");
  }
  return subtle().importKey("raw", asBufferSource(raw), { name: "ECDH", namedCurve: "P-256" }, false, []);
}

export async function derivePairSession(input: {
  roomId: string;
  roomPsk: Uint8Array;
  localPrivateKey: CryptoKey;
  localClientId: string;
  localSessionPub: string;
  peerClientId: string;
  peerSessionPub: string;
  capabilities: CapabilitySet;
}): Promise<PairSession> {
  const peerPublicKey = await importPeerPublicKey(input.peerSessionPub);
  const ecdhSecret = new Uint8Array(
    await subtle().deriveBits({ name: "ECDH", public: peerPublicKey }, input.localPrivateKey, 256)
  );
  const participants = [
    { clientId: input.localClientId, sessionPub: input.localSessionPub },
    { clientId: input.peerClientId, sessionPub: input.peerSessionPub }
  ].sort((a, b) => a.clientId.localeCompare(b.clientId) || a.sessionPub.localeCompare(b.sessionPub));
  const transcript = stableJson({
    v: 3,
    roomId: input.roomId,
    participants,
    capabilities: input.capabilities
  });
  const transcriptHashBytes = await sha256(transcript);
  const pairMaster = await hkdf(
    concatBytes(ecdhSecret, transcriptHashBytes),
    "secure-chat/v3/pair-master",
    input.roomPsk,
    32
  );
  const transcriptHash = base64urlEncode(transcriptHashBytes);
  const rootKey = await hkdf(pairMaster, "secure-chat/v3/root", transcriptHashBytes, 32);
  const sendLabel = `secure-chat/v3/send-chain/${input.localClientId}->${input.peerClientId}`;
  const recvLabel = `secure-chat/v3/send-chain/${input.peerClientId}->${input.localClientId}`;
  const mediaSendLabel = `secure-chat/v3/media-send-chain/${input.localClientId}->${input.peerClientId}`;
  const mediaRecvLabel = `secure-chat/v3/media-send-chain/${input.peerClientId}->${input.localClientId}`;
  const sendCK = await hkdf(pairMaster, utf8(sendLabel), transcriptHashBytes, 32);
  const recvCK = await hkdf(pairMaster, utf8(recvLabel), transcriptHashBytes, 32);
  const mediaSendCK = await hkdf(pairMaster, utf8(mediaSendLabel), transcriptHashBytes, 32);
  const mediaRecvCK = await hkdf(pairMaster, utf8(mediaRecvLabel), transcriptHashBytes, 32);
  ecdhSecret.fill(0);
  pairMaster.fill(0);
  return {
    peerClientId: input.peerClientId,
    transcriptHash,
    rootKey,
    sendCK,
    recvCK,
    mediaSendCK,
    mediaRecvCK
  };
}
