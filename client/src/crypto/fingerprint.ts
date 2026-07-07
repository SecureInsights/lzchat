import { base64urlDecode } from "./base64url";
import { concatBytes, utf8 } from "./bytes";
import { hmacSha256, sha256 } from "./kdf";
import type { MembersMessage } from "../protocol/types";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]!;
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31]!;
  }
  return output;
}

export function formatSafetyCode(value: string): string {
  return value.match(/.{1,4}/gu)?.join("-") ?? value;
}

export async function peerFingerprint(roomId: string, peerSessionPub: string): Promise<string> {
  const digest = await sha256(concatBytes(utf8("peer"), utf8(roomId), base64urlDecode(peerSessionPub)));
  return formatSafetyCode(base32Encode(digest).slice(0, 20));
}

export async function rosterDigest(members: MembersMessage["members"]): Promise<string> {
  const lines = members
    .map((member) => `${member.clientId}:${member.sessionPub}`)
    .sort((a, b) => a.localeCompare(b))
    .join("\n");
  const digest = await sha256(lines);
  return base32Encode(digest).slice(0, 20);
}

export async function roomSafetyCode(rosterKey: Uint8Array, digest: string): Promise<string> {
  const mac = await hmacSha256(rosterKey, digest);
  return formatSafetyCode(base32Encode(mac).slice(0, 20));
}
