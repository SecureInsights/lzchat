import { aesGcmDecrypt, aesGcmEncrypt } from "./aead";
import { base64urlDecode, base64urlEncode } from "./base64url";
import { asBufferSource, utf8, zeroize } from "./bytes";
import { hkdf, pbkdf2Sha256 } from "./kdf";
import { randomBytes } from "./random";

export type InviteMode = "single-link" | "two-channel";
export type InviteKdf = "pbkdf2-sha256" | "argon2id";

export type InviteSecret = {
  v: 3;
  roomSeed: string;
  createdAt: number;
  expiresAt: number | null;
  maxMembers: number;
  features: {
    files: boolean;
    privateMessages: boolean;
    coverTraffic: boolean;
  };
};

export type SingleLinkInvite = {
  v: 3;
  mode: "single-link";
  secret: InviteSecret;
};

export type InviteCapsule = {
  v: 3;
  mode: "two-channel";
  kdf: InviteKdf;
  format: "compact-v1";
  salt: string;
  iterations?: number;
  ops?: number;
  mem?: number;
  nonce: string;
  ct: string;
};

export type ParsedInvite = SingleLinkInvite | InviteCapsule;

export type RoomSecrets = {
  roomSeed: Uint8Array;
  roomSecret: Uint8Array;
  roomId: string;
  roomPsk: Uint8Array;
  rosterKey: Uint8Array;
  fileKey: Uint8Array;
};

export const INVITE_PBKDF2_DEFAULT_ITERATIONS = 1_200_000;
export const INVITE_PBKDF2_MIN_ITERATIONS = 1_200_000;
export const INVITE_PBKDF2_MAX_ITERATIONS = 5_000_000;

const COMPACT_TWO_CHANNEL_PREFIX = "c3.";
const COMPACT_SINGLE_LINK_PREFIX = "s3.";
const SINGLE_LINK_SEED_BYTES = 32;
const COMPACT_SECRET_BYTES = 51;
const COMPACT_CAPSULE_HEADER_BYTES = 36;
const COMPACT_KDF_PBKDF2_SHA256 = 1;
const COMPACT_FORMAT_SECRET_V1 = 1;
const COMPACT_SALT_BYTES = 16;
const COMPACT_NONCE_BYTES = 12;
const ROOM_SECRET_SALT = utf8("secure-chat/v3/room-secret/salt");
const ROOM_ID_SALT = utf8("secure-chat/v3/room-id/salt");

function normalizeInviteIterations(iterations: number | undefined): number {
  const value = iterations ?? INVITE_PBKDF2_DEFAULT_ITERATIONS;
  if (
    !Number.isSafeInteger(value) ||
    value < INVITE_PBKDF2_MIN_ITERATIONS ||
    value > INVITE_PBKDF2_MAX_ITERATIONS
  ) {
    throw new Error("unsupported invite iterations");
  }
  return value;
}

function assertUnixMs(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("invalid invite timestamp");
  }
}

function compactSecretBytes(secret: InviteSecret): Uint8Array {
  const roomSeed = base64urlDecode(secret.roomSeed);
  if (secret.v !== 3 || roomSeed.length !== 32) {
    throw new Error("invalid invite secret");
  }
  assertUnixMs(secret.createdAt);
  if (secret.expiresAt !== null) {
    assertUnixMs(secret.expiresAt);
  }
  if (!Number.isSafeInteger(secret.maxMembers) || secret.maxMembers <= 0 || secret.maxMembers > 255) {
    throw new Error("invalid invite member cap");
  }
  const out = new Uint8Array(COMPACT_SECRET_BYTES);
  const view = new DataView(asBufferSource(out).buffer);
  out[0] = 3;
  out.set(roomSeed, 1);
  view.setBigUint64(33, BigInt(secret.createdAt), false);
  view.setBigUint64(41, BigInt(secret.expiresAt ?? 0), false);
  out[49] = secret.maxMembers;
  out[50] =
    (secret.features.files ? 1 : 0) |
    (secret.features.privateMessages ? 2 : 0) |
    (secret.features.coverTraffic ? 4 : 0);
  return out;
}

function compactSecretFromBytes(bytes: Uint8Array): InviteSecret {
  if (bytes.length !== COMPACT_SECRET_BYTES || bytes[0] !== 3) {
    throw new Error("invalid compact invite secret");
  }
  const view = new DataView(asBufferSource(bytes).buffer);
  const createdAt = Number(view.getBigUint64(33, false));
  const expiresAtRaw = Number(view.getBigUint64(41, false));
  const maxMembers = bytes[49]!;
  const flags = bytes[50]!;
  assertUnixMs(createdAt);
  if (expiresAtRaw > 0) {
    assertUnixMs(expiresAtRaw);
  }
  if (maxMembers <= 0) {
    throw new Error("invalid invite member cap");
  }
  return {
    v: 3,
    roomSeed: base64urlEncode(bytes.slice(1, 33)),
    createdAt,
    expiresAt: expiresAtRaw === 0 ? null : expiresAtRaw,
    maxMembers,
    features: {
      files: (flags & 1) !== 0,
      privateMessages: (flags & 2) !== 0,
      coverTraffic: (flags & 4) !== 0
    }
  };
}

function defaultInviteSecret(roomSeed: string): InviteSecret {
  return {
    v: 3,
    roomSeed,
    createdAt: Date.now(),
    expiresAt: null,
    maxMembers: 16,
    features: {
      files: true,
      privateMessages: true,
      coverTraffic: false
    }
  };
}

function encodeCompactCapsule(capsule: InviteCapsule): string {
  if (capsule.kdf !== "pbkdf2-sha256" || capsule.ops !== undefined || capsule.mem !== undefined) {
    throw new Error("unsupported compact invite");
  }
  const salt = base64urlDecode(capsule.salt);
  const nonce = base64urlDecode(capsule.nonce);
  const ct = base64urlDecode(capsule.ct);
  if (salt.length !== COMPACT_SALT_BYTES || nonce.length !== COMPACT_NONCE_BYTES) {
    throw new Error("invalid compact invite");
  }
  const iterations = normalizeInviteIterations(capsule.iterations);
  const out = new Uint8Array(COMPACT_CAPSULE_HEADER_BYTES + ct.length);
  const view = new DataView(asBufferSource(out).buffer);
  out[0] = 3;
  out[1] = 2;
  out[2] = COMPACT_KDF_PBKDF2_SHA256;
  out[3] = COMPACT_FORMAT_SECRET_V1;
  view.setUint32(4, iterations, false);
  out.set(salt, 8);
  out.set(nonce, 24);
  out.set(ct, COMPACT_CAPSULE_HEADER_BYTES);
  return `${COMPACT_TWO_CHANNEL_PREFIX}${base64urlEncode(out)}`;
}

function decodeCompactCapsule(value: string): InviteCapsule {
  const bytes = base64urlDecode(value.slice(COMPACT_TWO_CHANNEL_PREFIX.length));
  if (
    bytes.length <= COMPACT_CAPSULE_HEADER_BYTES ||
    bytes[0] !== 3 ||
    bytes[1] !== 2 ||
    bytes[2] !== COMPACT_KDF_PBKDF2_SHA256
  ) {
    throw new Error("invalid compact invite");
  }
  const format = bytes[3];
  if (format !== COMPACT_FORMAT_SECRET_V1) {
    throw new Error("invalid compact invite format");
  }
  const view = new DataView(asBufferSource(bytes).buffer);
  const iterations = normalizeInviteIterations(view.getUint32(4, false));
  return {
    v: 3,
    mode: "two-channel",
    kdf: "pbkdf2-sha256",
    format: "compact-v1",
    iterations,
    salt: base64urlEncode(bytes.slice(8, 24)),
    nonce: base64urlEncode(bytes.slice(24, COMPACT_CAPSULE_HEADER_BYTES)),
    ct: base64urlEncode(bytes.slice(COMPACT_CAPSULE_HEADER_BYTES))
  };
}

export function createInviteSecret(options?: Partial<Omit<InviteSecret, "v" | "roomSeed" | "createdAt">>): InviteSecret {
  return {
    v: 3,
    roomSeed: base64urlEncode(randomBytes(32)),
    createdAt: Date.now(),
    expiresAt: options?.expiresAt ?? null,
    maxMembers: options?.maxMembers ?? 16,
    features: {
      files: options?.features?.files ?? true,
      privateMessages: options?.features?.privateMessages ?? true,
      coverTraffic: options?.features?.coverTraffic ?? false
    }
  };
}

export function encodeInvite(invite: ParsedInvite): string {
  if (invite.mode === "single-link") {
    const roomSeed = base64urlDecode(invite.secret.roomSeed);
    if (invite.secret.v !== 3 || roomSeed.length !== SINGLE_LINK_SEED_BYTES) {
      throw new Error("invalid invite secret");
    }
    return `${COMPACT_SINGLE_LINK_PREFIX}${base64urlEncode(roomSeed)}`;
  }
  return encodeCompactCapsule(invite);
}

export function decodeInvite(value: string): ParsedInvite {
  if (value.startsWith(COMPACT_SINGLE_LINK_PREFIX)) {
    const roomSeed = base64urlDecode(value.slice(COMPACT_SINGLE_LINK_PREFIX.length));
    if (roomSeed.length !== SINGLE_LINK_SEED_BYTES) {
      throw new Error("invalid compact invite");
    }
    return {
      v: 3,
      mode: "single-link",
      secret: defaultInviteSecret(base64urlEncode(roomSeed))
    };
  }
  if (value.startsWith(COMPACT_TWO_CHANNEL_PREFIX)) {
    return decodeCompactCapsule(value);
  }
  throw new Error("invalid compact invite");
}

export function createSingleLinkInvite(secret = createInviteSecret()): SingleLinkInvite {
  return { v: 3, mode: "single-link", secret };
}

export async function wrapInviteSecret(
  secret: InviteSecret,
  passphrase: string,
  options: { iterations?: number } = {}
): Promise<InviteCapsule> {
  if (passphrase.trim().length < 10) {
    throw new Error("passphrase too short");
  }
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const iterations = normalizeInviteIterations(options.iterations);
  const passKey = await pbkdf2Sha256(passphrase, salt, iterations);
  const inviteKey = await hkdf(passKey, "secure-chat/v3/invite-wrap", salt, 32);
  const plaintext = compactSecretBytes(secret);
  const ct = await (async () => {
    try {
      return await aesGcmEncrypt(inviteKey, nonce, utf8("invite-v3"), plaintext);
    } finally {
      zeroize(plaintext);
    }
  })();
  zeroize(passKey);
  zeroize(inviteKey);
  return {
    v: 3,
    mode: "two-channel",
    kdf: "pbkdf2-sha256",
    format: "compact-v1",
    salt: base64urlEncode(salt),
    iterations,
    nonce: base64urlEncode(nonce),
    ct: base64urlEncode(ct)
  };
}

export async function unwrapInviteCapsule(capsule: InviteCapsule, passphrase: string): Promise<InviteSecret> {
  if (capsule.kdf !== "pbkdf2-sha256") {
    throw new Error("unsupported invite kdf");
  }
  const salt = base64urlDecode(capsule.salt);
  const nonce = base64urlDecode(capsule.nonce);
  const iterations = normalizeInviteIterations(capsule.iterations);
  const passKey = await pbkdf2Sha256(passphrase, salt, iterations);
  const inviteKey = await hkdf(passKey, "secure-chat/v3/invite-wrap", salt, 32);
  try {
    const plaintext = await aesGcmDecrypt(inviteKey, nonce, utf8("invite-v3"), base64urlDecode(capsule.ct));
    if (capsule.format !== "compact-v1") {
      throw new Error("unsupported invite format");
    }
    const secret = compactSecretFromBytes(plaintext);
    if (secret.v !== 3 || base64urlDecode(secret.roomSeed).length !== 32) {
      throw new Error("invalid invite secret");
    }
    return secret;
  } finally {
    zeroize(passKey);
    zeroize(inviteKey);
  }
}

export async function inviteToSecret(invite: ParsedInvite, passphrase?: string): Promise<InviteSecret> {
  if (invite.mode === "single-link") {
    return invite.secret;
  }
  if (!passphrase) {
    throw new Error("passphrase required");
  }
  return unwrapInviteCapsule(invite, passphrase);
}

export async function deriveRoomSecrets(secret: InviteSecret): Promise<RoomSecrets> {
  const roomSeed = base64urlDecode(secret.roomSeed);
  if (roomSeed.length !== 32) {
    throw new Error("roomSeed must be 32 bytes");
  }
  const roomSecret = await hkdf(roomSeed, "secure-chat/v3/room-secret", ROOM_SECRET_SALT, 32);
  const roomIdBytes = await hkdf(roomSecret, "secure-chat/v3/room-id", ROOM_ID_SALT, 16);
  const roomPsk = await hkdf(roomSecret, "secure-chat/v3/room-psk", roomIdBytes, 32);
  const rosterKey = await hkdf(roomSecret, "secure-chat/v3/roster-key", roomIdBytes, 32);
  const fileKey = await hkdf(roomSecret, "secure-chat/v3/file-domain", roomIdBytes, 32);
  return {
    roomSeed,
    roomSecret,
    roomId: base64urlEncode(roomIdBytes),
    roomPsk,
    rosterKey,
    fileKey
  };
}

export function readInviteFromLocation(location: Location): string | null {
  const params = new URLSearchParams(location.hash.startsWith("#") ? location.hash.slice(1) : location.hash);
  return params.get("i");
}

export function clearLocationFragment(): void {
  if (window.location.hash) {
    history.replaceState(null, document.title, `${window.location.pathname}${window.location.search}`);
  }
}
