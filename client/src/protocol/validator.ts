import { base64urlDecode, base64urlEncode } from "../crypto/base64url";
import type { JoinMessage, MembersMessage, PlainPayload, RelayEnvelope, RelayKind, ServerMessage } from "./types";

export const MAX_RELAY_SIZE = 8 * 1024 * 1024;
export const MAX_ROOM_MEMBERS = 32;
export const MAX_MESSAGES_PER_WINDOW = 100;
export const RATE_WINDOW_MS = 10_000;
export const MAX_BAD_MESSAGES = 8;
export const CLIENT_TIMEOUT_MS = 90_000;
export const JOIN_TIMEOUT_MS = 10_000;

export const ROOM_ID_RE = /^[A-Za-z0-9_-]{16,64}$/u;
export const CLIENT_ID_RE = /^[A-Za-z0-9_-]{16,128}$/u;
export const PUBLIC_KEY_RE = /^[A-Za-z0-9_-]{40,256}$/u;
export const SMALL_TOKEN_RE = /^[A-Za-z0-9_-]{1,128}$/u;

export const RELAY_KINDS: ReadonlySet<RelayKind> = new Set([
  "profile",
  "text",
  "image",
  "file-meta",
  "file-chunk",
  "file-done",
  "private",
  "call-signal",
  "call-control",
  "call-media"
]);

export const MAX_TEXT_CHARS = 8_000;
export const MAX_DISPLAY_NAME_CHARS = 40;
export const MAX_ROOM_NAME_CHARS = 60;
export const MAX_IMAGE_BYTES_B64 = 8 * 1024 * 1024;
export const MAX_FILE_BYTES = 25 * 1024 * 1024;
export const FILE_CHUNK_BYTES = 256 * 1024;
export const MAX_FILE_CHUNKS = Math.ceil(MAX_FILE_BYTES / FILE_CHUNK_BYTES);
export const MAX_FILE_CHUNK_BYTES_B64 = Math.ceil((FILE_CHUNK_BYTES * 4) / 3) + 4;
export const MAX_FILE_NAME_CHARS = 180;
export const MAX_CALL_REASON_CHARS = 120;
export const MAX_CALL_VIDEO_BYTES_B64 = Math.ceil((128 * 1024 * 4) / 3) + 4;
export const MAX_CALL_AUDIO_BYTES_B64 = Math.ceil((16 * 1024 * 4) / 3) + 4;
export const MAX_CALL_MEDIA_CT_CHARS = 384 * 1024;

const INLINE_IMAGE_MIME_RE = /^image\/(?:png|jpeg|jpg|gif|webp|avif|bmp)$/u;
const MIME_TYPE_RE = /^[a-z][a-z0-9]*\/[a-z][a-z0-9]*(?:[.+-][a-z0-9]+)*$/u;
const CALL_VIDEO_CODEC_RE =
  /^(?:vp8|vp09(?:\.[A-Za-z0-9]{2,})+|av01(?:\.[A-Za-z0-9]{1,})+|avc[13]\.[A-Fa-f0-9]{6}|h(?:vc1|ev1)\.[A-Za-z0-9.]+)$/u;
const CALL_AUDIO_CODEC_RE = /^opus$/u;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validateCapabilities(value: unknown): JoinMessage["capabilities"] | null {
  if (!isObject(value)) {
    return null;
  }
  const maxRelayBytes = value.maxRelayBytes;
  if (
    value.ratchet !== "v1" ||
    value.aead !== "aes-gcm" ||
    typeof value.file !== "boolean" ||
    typeof maxRelayBytes !== "number" ||
    !Number.isSafeInteger(maxRelayBytes) ||
    maxRelayBytes <= 0 ||
    maxRelayBytes > MAX_RELAY_SIZE
  ) {
    return null;
  }
  return value as JoinMessage["capabilities"];
}

export function parseJsonObject(text: string): Record<string, unknown> | null {
  try {
    const value = JSON.parse(text);
    return isObject(value) ? value : null;
  } catch {
    return null;
  }
}

export function isValidRoomId(roomId: unknown): roomId is string {
  return typeof roomId === "string" && ROOM_ID_RE.test(roomId);
}

export function isValidClientId(clientId: unknown): clientId is string {
  return typeof clientId === "string" && CLIENT_ID_RE.test(clientId);
}

export function isValidPublicKey(publicKey: unknown): publicKey is string {
  return typeof publicKey === "string" && PUBLIC_KEY_RE.test(publicKey);
}

export function isValidSmallToken(token: unknown): token is string {
  return typeof token === "string" && SMALL_TOKEN_RE.test(token);
}

export function validateJoinMessage(value: unknown, expectedRoomId?: string): JoinMessage | null {
  if (!isObject(value)) {
    return null;
  }
  if (value.v !== 3 || value.t !== "join") {
    return null;
  }
  if (!isValidRoomId(value.roomId) || (expectedRoomId && value.roomId !== expectedRoomId)) {
    return null;
  }
  if (!isValidClientId(value.clientId) || !isValidPublicKey(value.sessionPub)) {
    return null;
  }
  if (value.identityPub !== undefined && !isValidPublicKey(value.identityPub)) {
    return null;
  }
  if (!validateCapabilities(value.capabilities)) {
    return null;
  }
  return value as JoinMessage;
}

export function validateMembersMessage(value: unknown, expectedRoomId?: string): MembersMessage | null {
  if (!isObject(value) || value.v !== 3 || value.t !== "members") {
    return null;
  }
  if (!isValidRoomId(value.roomId) || (expectedRoomId && value.roomId !== expectedRoomId)) {
    return null;
  }
  if (typeof value.epoch !== "number" || !Number.isSafeInteger(value.epoch) || value.epoch < 0) {
    return null;
  }
  if (!Array.isArray(value.members) || value.members.length > MAX_ROOM_MEMBERS) {
    return null;
  }
  for (const member of value.members) {
    if (!isObject(member)) {
      return null;
    }
    if (!isValidClientId(member.clientId) || !isValidPublicKey(member.sessionPub)) {
      return null;
    }
    if (member.identityPub !== undefined && !isValidPublicKey(member.identityPub)) {
      return null;
    }
    if (!validateCapabilities(member.capabilities)) {
      return null;
    }
  }
  return value as MembersMessage;
}

export function validateRelayEnvelope(
  value: unknown,
  expectedRoomId?: string,
  expectedFrom?: string,
  clientExists?: (clientId: string) => boolean
): RelayEnvelope | null {
  if (!isObject(value)) {
    return null;
  }
  if (value.v !== 3 || value.t !== "relay") {
    return null;
  }
  if (!isValidRoomId(value.roomId) || (expectedRoomId && value.roomId !== expectedRoomId)) {
    return null;
  }
  if (!isValidClientId(value.from) || (expectedFrom && value.from !== expectedFrom)) {
    return null;
  }
  if (!isValidClientId(value.to) || (clientExists && !clientExists(value.to))) {
    return null;
  }
  if (typeof value.kind !== "string" || !RELAY_KINDS.has(value.kind as RelayKind)) {
    return null;
  }
  const seq = value.seq;
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq <= 0) {
    return null;
  }
  if (!isValidSmallToken(value.nonce)) {
    return null;
  }
  const maxCtLength = value.kind === "call-media" ? MAX_CALL_MEDIA_CT_CHARS : MAX_RELAY_SIZE;
  if (typeof value.ct !== "string" || value.ct.length === 0 || value.ct.length > maxCtLength) {
    return null;
  }
  return value as RelayEnvelope;
}

function isTimestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isBase64Token(value: unknown, maxLength: number): value is string {
  if (
    typeof value !== "string" ||
    value.length > maxLength ||
    value.length % 4 === 1 ||
    !/^[A-Za-z0-9_-]*$/u.test(value)
  ) {
    return false;
  }
  try {
    return base64urlEncode(base64urlDecode(value)) === value;
  } catch {
    return false;
  }
}

function isValidMimeType(value: unknown): value is string {
  return typeof value === "string" && value.length <= 120 && MIME_TYPE_RE.test(value);
}

function isValidMediaSeq(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= 9_007_199_254_740_991;
}

function isValidDimension(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 && value <= 3840;
}

function isValidSampleRate(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 8_000 && value <= 192_000;
}

function isValidCallCodec(media: "audio" | "video", codec: unknown): codec is string {
  if (typeof codec !== "string" || codec.length === 0 || codec.length > 96) {
    return false;
  }
  return media === "video" ? CALL_VIDEO_CODEC_RE.test(codec) : CALL_AUDIO_CODEC_RE.test(codec);
}

function validateCallTargets(value: unknown): string[] | null {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_ROOM_MEMBERS) {
    return null;
  }
  for (const item of value) {
    if (!isValidClientId(item)) {
      return null;
    }
  }
  return value as string[];
}

export function validatePlainPayload(value: unknown, depth = 0): PlainPayload | null {
  if (!isObject(value) || depth > 2 || typeof value.type !== "string") {
    return null;
  }
  switch (value.type) {
    case "profile":
      if (typeof value.displayName !== "string" || value.displayName.length > MAX_DISPLAY_NAME_CHARS) {
        return null;
      }
      if (
        value.roomName !== undefined &&
        (typeof value.roomName !== "string" || value.roomName.length > MAX_ROOM_NAME_CHARS)
      ) {
        return null;
      }
      if (value.avatarSeed !== undefined && !isValidSmallToken(value.avatarSeed)) {
        return null;
      }
      return isTimestamp(value.createdAt) ? (value as PlainPayload) : null;
    case "text":
      if (typeof value.text !== "string" || value.text.length > MAX_TEXT_CHARS) {
        return null;
      }
      return isTimestamp(value.createdAt) ? (value as PlainPayload) : null;
    case "image":
      if (typeof value.mime !== "string" || !INLINE_IMAGE_MIME_RE.test(value.mime)) {
        return null;
      }
      if (!isBase64Token(value.bytes, MAX_IMAGE_BYTES_B64)) {
        return null;
      }
      return isTimestamp(value.createdAt) ? (value as PlainPayload) : null;
    case "file-meta":
      if (!isValidSmallToken(value.fileId)) {
        return null;
      }
      if (typeof value.name !== "string" || value.name.length === 0 || value.name.length > MAX_FILE_NAME_CHARS) {
        return null;
      }
      if (!isValidMimeType(value.mime)) {
        return null;
      }
      if (
        typeof value.size !== "number" ||
        !Number.isSafeInteger(value.size) ||
        value.size < 0 ||
        value.size > MAX_FILE_BYTES ||
        typeof value.chunks !== "number" ||
        !Number.isSafeInteger(value.chunks) ||
        value.chunks <= 0 ||
        value.chunks > MAX_FILE_CHUNKS ||
        value.chunks > Math.ceil(Math.max(value.size, 1) / FILE_CHUNK_BYTES)
      ) {
        return null;
      }
      return isTimestamp(value.createdAt) ? (value as PlainPayload) : null;
    case "file-chunk":
      if (!isValidSmallToken(value.fileId)) {
        return null;
      }
      if (
        typeof value.index !== "number" ||
        !Number.isSafeInteger(value.index) ||
        value.index < 0 ||
        typeof value.total !== "number" ||
        !Number.isSafeInteger(value.total) ||
        value.total <= 0 ||
        value.total > MAX_FILE_CHUNKS ||
        value.index >= value.total
      ) {
        return null;
      }
      return isBase64Token(value.bytes, MAX_FILE_CHUNK_BYTES_B64) ? (value as PlainPayload) : null;
    case "file-done":
      if (!isValidSmallToken(value.fileId)) {
        return null;
      }
      return isBase64Token(value.sha256, 64) ? (value as PlainPayload) : null;
    case "call-offer":
      if (
        !isValidSmallToken(value.callId) ||
        (value.media !== "audio" && value.media !== "video") ||
        value.mode !== "encoded-media"
      ) {
        return null;
      }
      if (!validateCallTargets(value.targetIds)) {
        return null;
      }
      return isTimestamp(value.createdAt) ? (value as PlainPayload) : null;
    case "call-answer":
      if (!isValidSmallToken(value.callId) || value.mode !== "encoded-media") {
        return null;
      }
      return isTimestamp(value.createdAt) ? (value as PlainPayload) : null;
    case "call-end":
      if (!isValidSmallToken(value.callId)) {
        return null;
      }
      if (value.reason !== undefined && (typeof value.reason !== "string" || value.reason.length > MAX_CALL_REASON_CHARS)) {
        return null;
      }
      return isTimestamp(value.createdAt) ? (value as PlainPayload) : null;
    case "call-media":
      if (
        !isValidSmallToken(value.callId) ||
        (value.media !== "audio" && value.media !== "video") ||
        !isValidMediaSeq(value.seq) ||
        !isValidCallCodec(value.media, value.codec) ||
        (value.chunkType !== "key" && value.chunkType !== "delta") ||
        !isValidMediaSeq(value.timestamp) ||
        typeof value.duration !== "number" ||
        !Number.isSafeInteger(value.duration) ||
        value.duration < 0 ||
        !isBase64Token(
          value.bytes,
          value.media === "audio" ? MAX_CALL_AUDIO_BYTES_B64 : MAX_CALL_VIDEO_BYTES_B64
        )
      ) {
        return null;
      }
      if (value.media === "video") {
        if (!isValidDimension(value.width) || !isValidDimension(value.height)) {
          return null;
        }
      } else if (!isValidSampleRate(value.sampleRate) || !isValidDimension(value.numberOfChannels)) {
        return null;
      }
      return isTimestamp(value.createdAt) ? (value as PlainPayload) : null;
    case "private": {
      const inner = validatePlainPayload(value.inner, depth + 1);
      return inner ? (value as PlainPayload) : null;
    }
    default:
      return null;
  }
}

export function validateServerMessage(value: unknown, expectedRoomId?: string): ServerMessage | null {
  const members = validateMembersMessage(value, expectedRoomId);
  if (members) {
    return members;
  }
  const relay = validateRelayEnvelope(value, expectedRoomId);
  if (relay) {
    return relay;
  }
  if (isObject(value) && value.v === 3 && value.t === "error" && typeof value.code === "string") {
    return value as ServerMessage;
  }
  return null;
}
