import { describe, expect, it } from "vitest";
import {
  MAX_FILE_BYTES,
  MAX_FILE_CHUNK_BYTES_B64,
  MAX_FILE_CHUNKS,
  MAX_CALL_AUDIO_BYTES_B64,
  MAX_CALL_VIDEO_BYTES_B64,
  validateJoinMessage,
  validatePlainPayload,
  validateRelayEnvelope
} from "../../client/src/protocol/validator";

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

  it("accepts encrypted call control relay envelopes", () => {
    expect(
      validateRelayEnvelope(
        {
          v: 3,
          t: "relay",
          roomId,
          from: clientA,
          to: clientB,
          kind: "call-control",
          seq: 1,
          nonce: "abc",
          ct: "ciphertext"
        },
        roomId,
        clientA,
        () => true
      )
    ).not.toBeNull();
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

  it("rejects dotted image MIME subtypes", () => {
    expect(
      validatePlainPayload({
        type: "image",
        mime: "image/x.foo",
        bytes: "AAA",
        createdAt: 1
      })
    ).toBeNull();

    expect(
      validatePlainPayload({
        type: "image",
        mime: "image/webp",
        bytes: "AAA",
        createdAt: 1
      })
    ).not.toBeNull();
  });

  it("validates file metadata MIME and chunk bounds", () => {
    const validMeta = {
      type: "file-meta",
      fileId: "filefilefilefile",
      name: "report.txt",
      mime: "text/plain",
      size: 1024,
      chunks: 1,
      createdAt: 1
    };

    expect(validatePlainPayload(validMeta)).not.toBeNull();
    expect(validatePlainPayload({ ...validMeta, mime: "text/html<script>" })).toBeNull();
    expect(validatePlainPayload({ ...validMeta, mime: "Text/Plain" })).toBeNull();
    expect(validatePlainPayload({ ...validMeta, mime: "application/java--script" })).toBeNull();
    expect(validatePlainPayload({ ...validMeta, size: MAX_FILE_BYTES + 1 })).toBeNull();
    expect(validatePlainPayload({ ...validMeta, chunks: MAX_FILE_CHUNKS + 1 })).toBeNull();
    expect(validatePlainPayload({ ...validMeta, size: 1, chunks: 2 })).toBeNull();
  });

  it("limits file chunk totals and encoded chunk size", () => {
    expect(
      validatePlainPayload({
        type: "file-chunk",
        fileId: "filefilefilefile",
        index: 0,
        total: MAX_FILE_CHUNKS + 1,
        bytes: "AAA"
      })
    ).toBeNull();
    expect(
      validatePlainPayload({
        type: "file-chunk",
        fileId: "filefilefilefile",
        index: 0,
        total: 1,
        bytes: "A".repeat(MAX_FILE_CHUNK_BYTES_B64 + 1)
      })
    ).toBeNull();
  });

  it("validates call signaling payloads", () => {
    const validOffer = {
      type: "call-offer",
      callId: "callcallcallcall",
      media: "video",
      mode: "encoded-media",
      targetIds: [clientB],
      createdAt: 1
    };
    expect(validatePlainPayload(validOffer)).not.toBeNull();
    expect(validatePlainPayload({ ...validOffer, media: "screen" })).toBeNull();
    expect(validatePlainPayload({ ...validOffer, targetIds: ["bad id"] })).toBeNull();
    expect(validatePlainPayload({ ...validOffer, mode: "webrtc" })).toBeNull();
    expect(
      validatePlainPayload({
        type: "call-answer",
        callId: "callcallcallcall",
        mode: "encoded-media",
        createdAt: 1
      })
    ).not.toBeNull();
    expect(
      validatePlainPayload({
        type: "call-media",
        callId: "callcallcallcall",
        media: "video",
        seq: 0,
        codec: "vp8",
        chunkType: "key",
        timestamp: 1,
        duration: 0,
        width: 480,
        height: 270,
        bytes: "AAA",
        createdAt: 1
      })
    ).not.toBeNull();
    expect(
      validatePlainPayload({
        type: "call-media",
        callId: "callcallcallcall",
        media: "video",
        seq: 0,
        codec: "avc1.42C01F",
        chunkType: "key",
        timestamp: 1,
        duration: 0,
        width: 480,
        height: 270,
        bytes: "AAA",
        createdAt: 1
      })
    ).not.toBeNull();
    expect(
      validatePlainPayload({
        type: "call-media",
        callId: "callcallcallcall",
        media: "video",
        seq: 0,
        codec: "avc1.42c01e",
        chunkType: "key",
        timestamp: 1,
        duration: 0,
        width: 480,
        height: 270,
        bytes: "AAA",
        createdAt: 1
      })
    ).not.toBeNull();
    expect(
      validatePlainPayload({
        type: "call-media",
        callId: "callcallcallcall",
        media: "video",
        seq: 0,
        codec: "av01.0.04M.08",
        chunkType: "key",
        timestamp: 1,
        duration: 0,
        width: 480,
        height: 270,
        bytes: "AAA",
        createdAt: 1
      })
    ).not.toBeNull();
    expect(
      validatePlainPayload({
        type: "call-media",
        callId: "callcallcallcall",
        media: "video",
        seq: 0,
        codec: "vp8<script>",
        chunkType: "key",
        timestamp: 1,
        duration: 0,
        width: 480,
        height: 270,
        bytes: "AAA",
        createdAt: 1
      })
    ).toBeNull();
    expect(
      validatePlainPayload({
        type: "call-media",
        callId: "callcallcallcall",
        media: "audio",
        seq: 0,
        codec: "vp8",
        chunkType: "key",
        timestamp: 1,
        duration: 0,
        sampleRate: 48000,
        numberOfChannels: 1,
        bytes: "AAA",
        createdAt: 1
      })
    ).toBeNull();
    expect(
      validatePlainPayload({
        type: "call-media",
        callId: "callcallcallcall",
        media: "audio",
        seq: 0,
        codec: "opus",
        chunkType: "key",
        timestamp: 1,
        duration: 0,
        sampleRate: 48000,
        numberOfChannels: 1,
        bytes: "A".repeat(MAX_CALL_AUDIO_BYTES_B64 + 1),
        createdAt: 1
      })
    ).toBeNull();
    expect(
      validatePlainPayload({
        type: "call-media",
        callId: "callcallcallcall",
        media: "video",
        seq: 0,
        codec: "vp8",
        chunkType: "key",
        timestamp: 1,
        duration: 0,
        width: 480,
        height: 270,
        bytes: "A".repeat(MAX_CALL_VIDEO_BYTES_B64 + 1),
        createdAt: 1
      })
    ).toBeNull();
  });
});
