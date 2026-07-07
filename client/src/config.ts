export const APP_NAME = "Secure Chat";
export const PROTOCOL_VERSION = 3;
export const BUILD_HASH = "__DEV_BUILD__";

export const FILE_LIMITS = {
  maxFileBytes: 25 * 1024 * 1024,
  maxBatchBytes: 100 * 1024 * 1024,
  maxFiles: 10,
  chunkBytes: 96 * 1024
} as const;

export function wsUrlForRoom(roomId: string): string {
  const url = new URL(window.location.href);
  const protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${url.host}/ws?room=${encodeURIComponent(roomId)}`;
}
