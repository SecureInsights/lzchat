import { describe, expect, it } from "vitest";
import { ReceiveRatchet, SendRatchet } from "../../client/src/crypto/ratchet";

describe("ratchet", () => {
  it("advances one-time message keys", async () => {
    const seed = new Uint8Array(32).fill(9);
    const send = new SendRatchet(seed);
    const a = await send.next();
    const b = await send.next();
    expect(a.seq).toBe(1);
    expect(b.seq).toBe(2);
    expect(a.messageKey).not.toEqual(b.messageKey);
  });

  it("serializes concurrent send key derivation", async () => {
    const seed = new Uint8Array(32).fill(7);
    const concurrent = new SendRatchet(seed);
    const sequential = new SendRatchet(seed);
    const [a, b, c] = await Promise.all([concurrent.next(), concurrent.next(), concurrent.next()]);
    const expected = [await sequential.next(), await sequential.next(), await sequential.next()];
    expect([a.seq, b.seq, c.seq]).toEqual([1, 2, 3]);
    expect([a.messageKey, b.messageKey, c.messageKey]).toEqual(expected.map((step) => step.messageKey));
  });

  it("rejects replay", async () => {
    const seed = new Uint8Array(32).fill(3);
    const recv = new ReceiveRatchet(seed);
    const key = await recv.messageKey(1, "text");
    expect(key).not.toBeNull();
    recv.markAccepted(1);
    expect(await recv.messageKey(1, "text")).toBeNull();
  });

  it("keeps skipped keys inside the out-of-order window", async () => {
    const seed = new Uint8Array(32).fill(5);
    const recv = new ReceiveRatchet(seed);
    const key3 = await recv.messageKey(3, "text");
    expect(key3).not.toBeNull();
    const key1 = await recv.messageKey(1, "text");
    expect(key1).not.toBeNull();
  });

  it("serializes concurrent receive key derivation", async () => {
    const seed = new Uint8Array(32).fill(6);
    const concurrent = new ReceiveRatchet(seed);
    const sequential = new ReceiveRatchet(seed);
    const [a, b, c] = await Promise.all([
      concurrent.messageKey(1, "call-media"),
      concurrent.messageKey(2, "call-media"),
      concurrent.messageKey(3, "call-media")
    ]);
    const expected = [
      await sequential.messageKey(1, "call-media"),
      await sequential.messageKey(2, "call-media"),
      await sequential.messageKey(3, "call-media")
    ];
    expect([a, b, c]).toEqual(expected);
  });
});
