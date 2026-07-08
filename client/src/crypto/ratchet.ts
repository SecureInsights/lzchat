import { base64urlEncode } from "./base64url";
import { utf8, zeroize } from "./bytes";
import { hkdf, seqInfo, sha256 } from "./kdf";

const DEFAULT_REPLAY_WINDOW = 128;
const DEFAULT_MAX_SKIPPED = 128;
const MESSAGE_KEY_SALT = utf8("secure-chat/v3/ratchet/message-key/salt");
const CHAIN_NEXT_SALT = utf8("secure-chat/v3/ratchet/chain-next/salt");

export async function deriveMessageKey(chainKey: Uint8Array, seq: number): Promise<Uint8Array> {
  return hkdf(chainKey, seqInfo("secure-chat/v3/message-key", seq), MESSAGE_KEY_SALT, 32);
}

export async function deriveNextChainKey(chainKey: Uint8Array, seq: number): Promise<Uint8Array> {
  return hkdf(chainKey, seqInfo("secure-chat/v3/chain-next", seq), CHAIN_NEXT_SALT, 32);
}

export async function deriveNonce(messageKey: Uint8Array, kind: string, seq: number, aad: Uint8Array): Promise<Uint8Array> {
  const aadHash = await sha256(aad);
  return hkdf(messageKey, seqInfo(`secure-chat/v3/nonce/${kind}`, seq), aadHash, 12);
}

export class SendRatchet {
  #chainKey: Uint8Array;
  #seq = 0;
  #pending = Promise.resolve();

  constructor(chainKey: Uint8Array) {
    this.#chainKey = new Uint8Array(chainKey);
  }

  async next(): Promise<{ seq: number; messageKey: Uint8Array }> {
    let release!: () => void;
    const previous = this.#pending;
    this.#pending = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      this.#seq += 1;
      const seq = this.#seq;
      const messageKey = await deriveMessageKey(this.#chainKey, seq);
      const nextChainKey = await deriveNextChainKey(this.#chainKey, seq);
      zeroize(this.#chainKey);
      this.#chainKey = nextChainKey;
      return { seq, messageKey };
    } finally {
      release();
    }
  }

  destroy(): void {
    zeroize(this.#chainKey);
  }
}

export class ReceiveRatchet {
  #chainKey: Uint8Array;
  #highestDerivedSeq = 0;
  #lastAcceptedSeq = 0;
  #seen = new Set<number>();
  #skipped = new Map<number, Uint8Array>();
  #pending = Promise.resolve();

  constructor(
    chainKey: Uint8Array,
    private readonly replayWindow = DEFAULT_REPLAY_WINDOW,
    private readonly maxSkipped = DEFAULT_MAX_SKIPPED
  ) {
    this.#chainKey = new Uint8Array(chainKey);
  }

  async messageKey(seq: number, _kind: string): Promise<Uint8Array | null> {
    let release!: () => void;
    const previous = this.#pending;
    this.#pending = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      if (!Number.isSafeInteger(seq) || seq <= 0) {
        return null;
      }
      if (this.#seen.has(seq)) {
        return null;
      }
      if (seq <= this.#lastAcceptedSeq - this.replayWindow) {
        return null;
      }
      const skipped = this.#skipped.get(seq);
      if (skipped) {
        this.#skipped.delete(seq);
        return skipped;
      }
      if (seq <= this.#highestDerivedSeq) {
        return null;
      }
      if (seq - this.#highestDerivedSeq > this.maxSkipped + 1) {
        return null;
      }
      while (this.#highestDerivedSeq < seq) {
        const nextSeq = this.#highestDerivedSeq + 1;
        const messageKey = await deriveMessageKey(this.#chainKey, nextSeq);
        const nextChainKey = await deriveNextChainKey(this.#chainKey, nextSeq);
        zeroize(this.#chainKey);
        this.#chainKey = nextChainKey;
        this.#highestDerivedSeq = nextSeq;
        if (nextSeq === seq) {
          return messageKey;
        }
        this.#skipped.set(nextSeq, messageKey);
        this.trimSkipped();
      }
      return null;
    } finally {
      release();
    }
  }

  markAccepted(seq: number): void {
    this.#seen.add(seq);
    this.#lastAcceptedSeq = Math.max(this.#lastAcceptedSeq, seq);
    const minRetainedSeq = this.#lastAcceptedSeq - this.replayWindow;
    this.#seen = new Set([...this.#seen].filter((seenSeq) => seenSeq > minRetainedSeq));
  }

  restoreSkipped(seq: number, messageKey: Uint8Array): void {
    if (this.#seen.has(seq)) {
      zeroize(messageKey);
      return;
    }
    if (seq <= this.#lastAcceptedSeq - this.replayWindow) {
      zeroize(messageKey);
      return;
    }
    const existing = this.#skipped.get(seq);
    if (existing) {
      zeroize(existing);
    }
    this.#skipped.set(seq, new Uint8Array(messageKey));
    this.trimSkipped();
  }

  destroy(): void {
    zeroize(this.#chainKey);
    for (const value of this.#skipped.values()) {
      zeroize(value);
    }
    this.#skipped.clear();
  }

  private trimSkipped(): void {
    while (this.#skipped.size > this.maxSkipped) {
      const firstKey = this.#skipped.keys().next().value as number | undefined;
      if (firstKey === undefined) {
        return;
      }
      const value = this.#skipped.get(firstKey);
      if (value) {
        zeroize(value);
      }
      this.#skipped.delete(firstKey);
    }
  }
}

export async function debugChainFingerprint(chainKey: Uint8Array): Promise<string> {
  return base64urlEncode(await sha256(chainKey)).slice(0, 16);
}
