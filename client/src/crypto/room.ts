import { aesGcmDecrypt, aesGcmEncrypt } from "./aead";
import { base64urlDecode, base64urlEncode, stringFromBase64url } from "./base64url";
import { fromUtf8, utf8, zeroize } from "./bytes";
import { hkdf, pbkdf2Sha256 } from "./kdf";
import { randomBytes } from "./random";
import { stableJson } from "./stable-json";

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

export const INVITE_PBKDF2_DEFAULT_ITERATIONS = 600_000;
export const INVITE_PBKDF2_MIN_ITERATIONS = 600_000;
export const INVITE_PBKDF2_MAX_ITERATIONS = 5_000_000;

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
  return base64urlEncode(utf8(stableJson(invite)));
}

export function decodeInvite(value: string): ParsedInvite {
  const parsed = JSON.parse(stringFromBase64url(value)) as ParsedInvite;
  if (parsed?.v !== 3 || (parsed.mode !== "single-link" && parsed.mode !== "two-channel")) {
    throw new Error("invalid invite");
  }
  return parsed;
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
  const ct = await aesGcmEncrypt(inviteKey, nonce, utf8("invite-v3"), utf8(stableJson(secret)));
  zeroize(passKey);
  zeroize(inviteKey);
  return {
    v: 3,
    mode: "two-channel",
    kdf: "pbkdf2-sha256",
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
    const secret = JSON.parse(fromUtf8(plaintext)) as InviteSecret;
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
  return params.get("invite");
}

export function clearLocationFragment(): void {
  if (window.location.hash) {
    history.replaceState(null, document.title, `${window.location.pathname}${window.location.search}`);
  }
}
