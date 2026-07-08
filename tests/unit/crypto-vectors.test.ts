import { describe, expect, it } from "vitest";
import { derivePairSession, generateSessionKeys, importPeerPublicKey } from "../../client/src/crypto/handshake";
import { deriveRoomSecrets, type InviteSecret } from "../../client/src/crypto/room";
import { base64urlEncode } from "../../client/src/crypto/base64url";
import { ReceiveRatchet, SendRatchet } from "../../client/src/crypto/ratchet";
import { openPayload, sealPayload } from "../../client/src/protocol/envelope";
import type { CapabilitySet } from "../../client/src/protocol/types";
import { hkdf } from "../../client/src/crypto/kdf";

const secret: InviteSecret = {
  v: 3,
  roomSeed: base64urlEncode(new Uint8Array(32).fill(11)),
  createdAt: 1,
  expiresAt: null,
  maxMembers: 16,
  features: { files: true, privateMessages: true, coverTraffic: false }
};

describe("pairwise crypto", () => {
  it("requires explicit non-empty HKDF salt", async () => {
    await expect(hkdf(new Uint8Array(32), "test", new Uint8Array(), 32)).rejects.toThrow("hkdf salt required");
  });

  it("rejects invalid P-256 public points through WebCrypto", async () => {
    const zeroPoint = base64urlEncode(new Uint8Array([4, ...new Uint8Array(64)]));
    await expect(importPeerPublicKey(zeroPoint)).rejects.toThrow();
  });

  it("decrypts sealed payload and rejects AAD tampering", async () => {
    const room = await deriveRoomSecrets(secret);
    const alice = await generateSessionKeys();
    const bob = await generateSessionKeys();
    const capabilities: CapabilitySet = { ratchet: "v1", aead: "aes-gcm", file: true, maxRelayBytes: 8 * 1024 * 1024 };
    const alicePair = await derivePairSession({
      roomId: room.roomId,
      roomPsk: room.roomPsk,
      localPrivateKey: alice.privateKey,
      localClientId: "alicealicealice1",
      localSessionPub: alice.publicKeyToken,
      peerClientId: "bobbobbobbobbob2",
      peerSessionPub: bob.publicKeyToken,
      capabilities
    });
    const bobPair = await derivePairSession({
      roomId: room.roomId,
      roomPsk: room.roomPsk,
      localPrivateKey: bob.privateKey,
      localClientId: "bobbobbobbobbob2",
      localSessionPub: bob.publicKeyToken,
      peerClientId: "alicealicealice1",
      peerSessionPub: alice.publicKeyToken,
      capabilities
    });
    expect(alicePair.transcriptHash).toBe(bobPair.transcriptHash);
    const envelope = await sealPayload({
      roomId: room.roomId,
      from: "alicealicealice1",
      to: "bobbobbobbobbob2",
      kind: "text",
      transcriptHash: alicePair.transcriptHash,
      ratchet: new SendRatchet(alicePair.sendCK),
      payload: { type: "text", text: "hello", createdAt: 1 }
    });
    const opened = await openPayload(envelope, bobPair.transcriptHash, new ReceiveRatchet(bobPair.recvCK));
    expect(opened).toEqual({ type: "text", text: "hello", createdAt: 1 });
    const tampered = { ...envelope, kind: "profile" as const };
    const rejected = await openPayload(tampered, bobPair.transcriptHash, new ReceiveRatchet(bobPair.recvCK));
    expect(rejected).toBeNull();
  });
});
