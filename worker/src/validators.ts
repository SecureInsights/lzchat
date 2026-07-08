export type CapabilitySet = {
  ratchet: "v1";
  aead: "aes-gcm";
  file: boolean;
  maxRelayBytes: number;
};

export type JoinMessage = {
  v: 3;
  t: "join";
  roomId: string;
  clientId: string;
  sessionPub: string;
  identityPub?: string;
  capabilities: CapabilitySet;
};

export type RelayKind =
  | "profile"
  | "text"
  | "image"
  | "file-meta"
  | "file-chunk"
  | "file-done"
  | "private"
  | "call-signal"
  | "call-control"
  | "call-media";

export type RelayEnvelope = {
  v: 3;
  t: "relay";
  roomId: string;
  from: string;
  to: string;
  kind: RelayKind;
  seq: number;
  nonce: string;
  ct: string;
};

export const MAX_RELAY_SIZE = 8 * 1024 * 1024;
export const MAX_ROOM_MEMBERS = 32;
export const MAX_MESSAGES_PER_WINDOW = 100;
export const MAX_CALL_MEDIA_MESSAGES_PER_WINDOW = 2_000;
export const MAX_CALL_MEDIA_BYTES_PER_WINDOW = 8 * 1024 * 1024;
export const RATE_WINDOW_MS = 10_000;
export const MAX_BAD_MESSAGES = 8;
export const CLIENT_TIMEOUT_MS = 90_000;
export const JOIN_TIMEOUT_MS = 10_000;

export const ROOM_ID_RE = /^[A-Za-z0-9_-]{16,64}$/u;
export const CLIENT_ID_RE = /^[A-Za-z0-9_-]{16,128}$/u;
export const PUBLIC_KEY_RE = /^[A-Za-z0-9_-]{40,256}$/u;
export const SMALL_TOKEN_RE = /^[A-Za-z0-9_-]{1,128}$/u;

const RELAY_KINDS = new Set<RelayKind>([
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

export function validateJoinMessage(value: unknown, expectedRoomId: string): JoinMessage | null {
  if (!isObject(value) || value.v !== 3 || value.t !== "join") {
    return null;
  }
  if (typeof value.roomId !== "string" || value.roomId !== expectedRoomId || !ROOM_ID_RE.test(value.roomId)) {
    return null;
  }
  if (typeof value.clientId !== "string" || !CLIENT_ID_RE.test(value.clientId)) {
    return null;
  }
  if (typeof value.sessionPub !== "string" || !PUBLIC_KEY_RE.test(value.sessionPub)) {
    return null;
  }
  if (value.identityPub !== undefined && (typeof value.identityPub !== "string" || !PUBLIC_KEY_RE.test(value.identityPub))) {
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
  expectedRoomId: string,
  expectedFrom: string,
  clientExists: (clientId: string) => boolean
): RelayEnvelope | null {
  if (!isObject(value) || value.v !== 3 || value.t !== "relay") {
    return null;
  }
  if (typeof value.roomId !== "string" || value.roomId !== expectedRoomId || !ROOM_ID_RE.test(value.roomId)) {
    return null;
  }
  if (typeof value.from !== "string" || value.from !== expectedFrom || !CLIENT_ID_RE.test(value.from)) {
    return null;
  }
  if (typeof value.to !== "string" || !CLIENT_ID_RE.test(value.to) || !clientExists(value.to)) {
    return null;
  }
  if (typeof value.kind !== "string" || !RELAY_KINDS.has(value.kind as RelayKind)) {
    return null;
  }
  const seq = value.seq;
  if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq <= 0) {
    return null;
  }
  if (typeof value.nonce !== "string" || !SMALL_TOKEN_RE.test(value.nonce)) {
    return null;
  }
  if (typeof value.ct !== "string" || value.ct.length === 0 || value.ct.length > MAX_RELAY_SIZE) {
    return null;
  }
  return value as RelayEnvelope;
}
