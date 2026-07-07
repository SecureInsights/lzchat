import { describe, expect, it } from "vitest";
import { base64urlEncode } from "../../client/src/crypto/base64url";
import {
  createSingleLinkInvite,
  decodeInvite,
  deriveRoomSecrets,
  encodeInvite,
  unwrapInviteCapsule,
  wrapInviteSecret,
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
  it("encodes single-link invite", () => {
    const token = encodeInvite(createSingleLinkInvite(fixtureSecret));
    expect(decodeInvite(token).mode).toBe("single-link");
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
    const opened = await unwrapInviteCapsule(capsule, "correct horse battery staple");
    expect(opened.roomSeed).toBe(fixtureSecret.roomSeed);
    await expect(unwrapInviteCapsule(capsule, "wrong passphrase")).rejects.toThrow();
  });

  it("supports upgraded invite PBKDF2 iterations", async () => {
    const capsule = await wrapInviteSecret(fixtureSecret, "correct horse battery staple", { iterations: 600_001 });
    const opened = await unwrapInviteCapsule(capsule, "correct horse battery staple");
    expect(capsule.iterations).toBe(600_001);
    expect(opened.roomSeed).toBe(fixtureSecret.roomSeed);
  });

  it("rejects downgraded invite PBKDF2 iterations", async () => {
    const capsule = await wrapInviteSecret(fixtureSecret, "correct horse battery staple");
    await expect(
      unwrapInviteCapsule({ ...capsule, iterations: 100_000 }, "correct horse battery staple")
    ).rejects.toThrow("unsupported invite iterations");
  });
});
