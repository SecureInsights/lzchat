export const APP_NAME = "Secure Chat";

export function wsUrlForRoom(roomId: string): string {
  const url = new URL(window.location.href);
  const protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${url.host}/ws?room=${encodeURIComponent(roomId)}`;
}
