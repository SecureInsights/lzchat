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
  "private"
]);

export const MAX_TEXT_CHARS = 8_000;
export const MAX_DISPLAY_NAME_CHARS = 40;
export const MAX_IMAGE_BYTES_B64 = 8 * 1024 * 1024;
export const MAX_FILE_NAME_CHARS = 180;

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
  if (typeof value.ct !== "string" || value.ct.length === 0 || value.ct.length > MAX_RELAY_SIZE) {
    return null;
  }
  return value as RelayEnvelope;
}

function isTimestamp(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isBase64Token(value: unknown, maxLength: number): value is string {
  return typeof value === "string" && value.length <= maxLength && /^[A-Za-z0-9_-]*$/u.test(value);
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
      if (typeof value.mime !== "string" || !/^image\/[A-Za-z0-9.+-]{1,40}$/u.test(value.mime)) {
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
      if (typeof value.mime !== "string" || value.mime.length > 120) {
        return null;
      }
      if (
        typeof value.size !== "number" ||
        !Number.isSafeInteger(value.size) ||
        value.size < 0 ||
        typeof value.chunks !== "number" ||
        !Number.isSafeInteger(value.chunks) ||
        value.chunks <= 0
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
        value.index >= value.total
      ) {
        return null;
      }
      return isBase64Token(value.bytes, MAX_RELAY_SIZE) ? (value as PlainPayload) : null;
    case "file-done":
      if (!isValidSmallToken(value.fileId)) {
        return null;
      }
      return isBase64Token(value.sha256, 64) ? (value as PlainPayload) : null;
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
