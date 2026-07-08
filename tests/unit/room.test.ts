import { describe, expect, it } from "vitest";
import { base64urlEncode } from "../../client/src/crypto/base64url";
import {
  createSingleLinkInvite,
  decodeInvite,
  deriveRoomSecrets,
  encodeInvite,
  readInviteFromLocation,
  unwrapInviteCapsule,
  wrapInviteSecret,
  type InviteCapsule,
  type InviteSecret
} from "../../client/src/crypto/room";

const fixtureSecret: InviteSecret = {
  v: 3,
  roomSeed: base64urlEncode(new Uint8Array(32).fill(7)),
  createdAt: 1_700_000_000_000,
  expiresAt: null,
  maxMembers: 16,
  features: {
    files: true,
    privateMessages: true,
    coverTraffic: false
  }
};

describe("room invite", () => {
  it("encodes compact single-link invites and rejects legacy JSON tokens", () => {
    const invite = createSingleLinkInvite(fixtureSecret);
    const token = encodeInvite(invite);
    expect(token.startsWith("s3.")).toBe(true);
    expect(token.length).toBe(46);
    const decoded = decodeInvite(token);
    expect(decoded.mode).toBe("single-link");
    if (decoded.mode !== "single-link") {
      throw new Error("expected single-link invite");
    }
    expect(decoded.secret.roomSeed).toBe(fixtureSecret.roomSeed);
    expect(decoded.secret.maxMembers).toBe(16);
    expect(decoded.secret.features.files).toBe(true);

    const legacyToken = base64urlEncode(new TextEncoder().encode(JSON.stringify(invite)));
    expect(() => decodeInvite(legacyToken)).toThrow("invalid compact invite");
  });

  it("reads short invite fragments", () => {
    const token = encodeInvite(createSingleLinkInvite(fixtureSecret));
    expect(readInviteFromLocation({ hash: `#i=${token}` } as Location)).toBe(token);
    expect(readInviteFromLocation({ hash: `#invite=${token}` } as Location)).toBeNull();
  });

  it("derives stable room id and keys", async () => {
    const a = await deriveRoomSecrets(fixtureSecret);
    const b = await deriveRoomSecrets(fixtureSecret);
    expect(a.roomId).toBe(b.roomId);
    expect(a.roomPsk).toEqual(b.roomPsk);
    expect(a.rosterKey).toHaveLength(32);
  });

  it("wraps invite with a separate passphrase", async () => {
    const capsule = await wrapInviteSecret(fixtureSecret, "correct horse battery staple");
    const token = encodeInvite(capsule);
    expect(token.startsWith("c3.")).toBe(true);
    expect(token.length).toBeLessThan(180);
    const decoded = decodeInvite(token) as InviteCapsule;
    const opened = await unwrapInviteCapsule(capsule, "correct horse battery staple");
    const openedFromToken = await unwrapInviteCapsule(decoded, "correct horse battery staple");
    expect(capsule.iterations).toBeGreaterThanOrEqual(1_200_000);
    expect(opened.roomSeed).toBe(fixtureSecret.roomSeed);
    expect(openedFromToken.roomSeed).toBe(fixtureSecret.roomSeed);
    await expect(unwrapInviteCapsule(capsule, "wrong passphrase")).rejects.toThrow();
  });

  it("supports upgraded invite PBKDF2 iterations", async () => {
    const capsule = await wrapInviteSecret(fixtureSecret, "correct horse battery staple", { iterations: 1_200_001 });
    const opened = await unwrapInviteCapsule(capsule, "correct horse battery staple");
    expect(capsule.iterations).toBe(1_200_001);
    expect(opened.roomSeed).toBe(fixtureSecret.roomSeed);
  });

  it("rejects downgraded invite PBKDF2 iterations", async () => {
    const capsule = await wrapInviteSecret(fixtureSecret, "correct horse battery staple");
    await expect(
      unwrapInviteCapsule({ ...capsule, iterations: 100_000 }, "correct horse battery staple")
    ).rejects.toThrow("unsupported invite iterations");
  });
});
