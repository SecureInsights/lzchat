import { describe, expect, it } from "vitest";
import { validateJoinMessage, validatePlainPayload, validateRelayEnvelope } from "../../client/src/protocol/validator";

const roomId = "abcdefghijklmnop";
const clientA = "clientclientclientA";
const clientB = "clientclientclientB";
const sessionPub = "A".repeat(88);

describe("envelope validator", () => {
  it("accepts a valid join", () => {
    expect(
      validateJoinMessage(
        {
          v: 3,
          t: "join",
          roomId,
          clientId: clientA,
          sessionPub,
          capabilities: { ratchet: "v1", aead: "aes-gcm", file: true, maxRelayBytes: 1024 }
        },
        roomId
      )
    ).not.toBeNull();
  });

  it("rejects forged relay sender", () => {
    expect(
      validateRelayEnvelope(
        {
          v: 3,
          t: "relay",
          roomId,
          from: clientB,
          to: clientA,
          kind: "text",
          seq: 1,
          nonce: "abc",
          ct: "ciphertext"
        },
        roomId,
        clientA,
        () => true
      )
    ).toBeNull();
  });

  it("rejects unknown relay target", () => {
    expect(
      validateRelayEnvelope(
        {
          v: 3,
          t: "relay",
          roomId,
          from: clientA,
          to: clientB,
          kind: "text",
          seq: 1,
          nonce: "abc",
          ct: "ciphertext"
        },
        roomId,
        clientA,
        () => false
      )
    ).toBeNull();
  });

  it("rejects invalid base64url payload lengths", () => {
    expect(
      validatePlainPayload({
        type: "image",
        mime: "image/png",
        bytes: "A",
        createdAt: 1
      })
    ).toBeNull();

    expect(
      validatePlainPayload({
        type: "file-chunk",
        fileId: "filefilefilefile",
        index: 0,
        total: 1,
        bytes: "A"
      })
    ).toBeNull();

    expect(
      validatePlainPayload({
        type: "file-chunk",
        fileId: "filefilefilefile",
        index: 0,
        total: 1,
        bytes: "AAA"
      })
    ).not.toBeNull();
  });
});
