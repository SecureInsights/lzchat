import type { JoinMessage, RelayEnvelope, RelayKind } from "./types";

export const MAX_RELAY_SIZE = 8 * 1024 * 1024;
export const MAX_ROOM_MEMBERS = 32;
export const MAX_MESSAGES_PER_WINDOW = 100;
export const RATE_WINDOW_MS = 10_000;
export const MAX_BAD_MESSAGES = 8;
export const CLIENT_TIMEOUT_MS = 90_000;

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

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
  if (!isObject(value.capabilities)) {
    return null;
  }
  const capabilities = value.capabilities;
  const maxRelayBytes = capabilities.maxRelayBytes;
  if (
    capabilities.ratchet !== "v1" ||
    capabilities.aead !== "aes-gcm" ||
    typeof capabilities.file !== "boolean" ||
    typeof maxRelayBytes !== "number" ||
    !Number.isSafeInteger(maxRelayBytes) ||
    maxRelayBytes <= 0 ||
    maxRelayBytes > MAX_RELAY_SIZE
  ) {
    return null;
  }
  return value as JoinMessage;
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
