export const PROTOCOL_VERSION = 3;

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

export type MembersMessage = {
  v: 3;
  t: "members";
  roomId: string;
  epoch: number;
  members: Array<{
    clientId: string;
    sessionPub: string;
    identityPub?: string;
    capabilities: CapabilitySet;
  }>;
};

export type RelayKind = "profile" | "text" | "image" | "file-meta" | "file-chunk" | "file-done" | "private";

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

export type ServerMessage = MembersMessage | RelayEnvelope | { v: 3; t: "error"; code: string };

export type PlainPayload =
  | { type: "profile"; displayName: string; avatarSeed?: string; createdAt: number }
  | { type: "text"; text: string; createdAt: number }
  | { type: "image"; mime: string; bytes: string; createdAt: number }
  | { type: "file-meta"; fileId: string; name: string; mime: string; size: number; chunks: number; createdAt: number }
  | { type: "file-chunk"; fileId: string; index: number; total: number; bytes: string }
  | { type: "file-done"; fileId: string; sha256: string }
  | { type: "private"; inner: PlainPayload };

export type RelayAad = {
  v: 3;
  t: "relay";
  roomId: string;
  from: string;
  to: string;
  kind: string;
  seq: number;
  transcriptHash: string;
};
