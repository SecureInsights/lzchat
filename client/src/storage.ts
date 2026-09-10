const PROFILE_CACHE_PREFIX = "lzchat/profile-cache/";
const PROFILE_CACHE_MAX = 200;

type CachedProfile = { name: string; seenAt: number };

type ProfileCache = Record<string, CachedProfile>;

/**
 * 按 (roomId, sessionPub) 缓存成员昵称，让本机重进房间时立即显示老成员的真实昵称，
 * 不必等待加密 profile 往返。sessionPub 每次进房都会更换，因此只对未离房的成员命中；
 * 按 roomId 隔离，避免昵称跨房间关联。
 */
export function loadCachedDisplayName(roomId: string, sessionPub: string): string | null {
  try {
    const raw = window.localStorage.getItem(PROFILE_CACHE_PREFIX + roomId);
    if (!raw) {
      return null;
    }
    const entries = JSON.parse(raw) as ProfileCache;
    const name = entries[sessionPub]?.name;
    return typeof name === "string" && name.length > 0 ? name : null;
  } catch {
    return null;
  }
}

export function saveCachedDisplayName(roomId: string, sessionPub: string, name: string): void {
  if (!name) {
    return;
  }
  try {
    const key = PROFILE_CACHE_PREFIX + roomId;
    const raw = window.localStorage.getItem(key);
    const entries = (raw ? JSON.parse(raw) : {}) as ProfileCache;
    entries[sessionPub] = { name, seenAt: Date.now() };
    const ids = Object.keys(entries);
    if (ids.length > PROFILE_CACHE_MAX) {
      ids.sort((a, b) => (entries[a]?.seenAt ?? 0) - (entries[b]?.seenAt ?? 0));
      for (const id of ids.slice(0, ids.length - PROFILE_CACHE_MAX)) {
        delete entries[id];
      }
    }
    window.localStorage.setItem(key, JSON.stringify(entries));
  } catch {
    // 存储不可用（隐私模式/配额满）时静默跳过，仅影响下次重进的显示速度。
  }
}
