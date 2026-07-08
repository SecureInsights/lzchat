import "./style.css";
import emojiDataUrl from "emoji-picker-element-data/zh/emojibase/data.json?url";
import { APP_NAME, BUILD_HASH, PROTOCOL_VERSION, wsUrlForRoom } from "./config";
import { base64urlDecode, base64urlEncode } from "./crypto/base64url";
import { peerFingerprint, roomSafetyCode, rosterDigest } from "./crypto/fingerprint";
import {
  derivePairSession,
  generateSessionKeys,
  type PairSession,
  type SessionKeys
} from "./crypto/handshake";
import { randomBytes } from "./crypto/random";
import { ReceiveRatchet, SendRatchet } from "./crypto/ratchet";
import { asBufferSource, concatBytes, zeroize } from "./crypto/bytes";
import {
  clearLocationFragment,
  createInviteSecret,
  createSingleLinkInvite,
  decodeInvite,
  deriveRoomSecrets,
  encodeInvite,
  inviteToSecret,
  readInviteFromLocation,
  wrapInviteSecret,
  type InviteSecret,
  type ParsedInvite,
  type RoomSecrets
} from "./crypto/room";
import { openPayload, sealPayload } from "./protocol/envelope";
import type {
  CapabilitySet,
  JoinMessage,
  MembersMessage,
  PlainPayload,
  RelayEnvelope,
  RelayKind,
  ServerMessage
} from "./protocol/types";
import { validateRelayEnvelope } from "./protocol/validator";
import { safeDownload } from "./security/download";
import { el, removeChildren, setDataset } from "./security/safe-dom";
import { WsClient } from "./transport/ws-client";

type PeerRuntime = {
  clientId: string;
  sessionPub: string;
  displayName: string;
  capabilities: CapabilitySet;
  pair: PairSession;
  sendRatchet: SendRatchet;
  recvRatchet: ReceiveRatchet;
  fingerprint: string;
  profileSent: boolean;
  messageWindow: number[];
  decryptFailures: number;
  lastFailureNoticeAt: number;
};

type ChatMessage = {
  id: string;
  own: boolean;
  author: string;
  kind: "text" | "image" | "file";
  createdAt: number;
  scope: "room" | "private";
  text?: string;
  imageUrl?: string;
  imageMime?: string;
  fileName?: string;
  fileSize?: number;
  fileBlob?: Blob;
  peerName?: string;
};

type Runtime = {
  roomName: string;
  displayName: string;
  mode: "single-link" | "two-channel";
  room: RoomSecrets;
  clientId: string;
  session: SessionKeys;
  capabilities: CapabilitySet;
  ws: WsClient;
  peers: Map<string, PeerRuntime>;
  pendingRelays: Map<string, RelayEnvelope[]>;
  members: MembersMessage["members"];
  messages: ChatMessage[];
  status: string;
  safetyCode: string;
  privatePeerId: string | null;
  roomUnread: number;
  privateUnread: Map<string, number>;
  inviteLink: string | null;
  invitePassphrase: string;
  inviteMode: "single-link" | "two-channel";
  incomingFiles: Map<string, IncomingFile>;
  notificationsEnabled: boolean;
  soundEnabled: boolean;
  lastNotificationAt: number;
};

type DeliveryContext = {
  targets: PeerRuntime[];
  scope: "room" | "private";
  peerName?: string;
};

type IncomingFile = {
  fileId: string;
  from: string;
  author: string;
  scope: "room" | "private";
  peerName?: string;
  name: string;
  mime: string;
  size: number;
  chunks: number;
  createdAt: number;
  parts: Array<Uint8Array | undefined>;
  received: number;
  receivedBytes: number;
  startedAt: number;
};

type EmojiRecord = {
  annotation: string;
  emoji: string;
  group: number;
  order: number;
  emoticon?: string;
  tags?: string[];
};

type EmojiCategory = {
  group: number;
  icon: string;
  label: string;
};

const app = document.querySelector<HTMLElement>("#app");
if (!app) {
  throw new Error("missing app root");
}
const appRoot = app;

const pendingInviteToken = readInviteFromLocation(window.location);
if (pendingInviteToken) {
  clearLocationFragment();
}

let runtime: Runtime | null = null;
let notificationAudioContext: AudioContext | null = null;
const MAX_RENDERED_MESSAGES = 500;
const PEER_MESSAGE_WINDOW_MS = 10_000;
const PEER_MAX_MESSAGES_PER_WINDOW = 120;
const FAILURE_NOTICE_INTERVAL_MS = 5_000;
const NOTIFICATION_THROTTLE_MS = 900;
const MAX_PENDING_RELAYS_PER_PEER = 32;
const MAX_INLINE_IMAGE_BYTES = 3 * 1024 * 1024;
const MAX_FILE_BYTES = 25 * 1024 * 1024;
const MAX_FILE_BATCH = 10;
const MAX_FILE_BATCH_BYTES = 100 * 1024 * 1024;
const FILE_CHUNK_BYTES = 256 * 1024;
const FILE_RECEIVE_TIMEOUT_MS = 2 * 60 * 1000;
const MAX_INCOMING_FILES_PER_PEER = 3;
const MAX_INCOMING_FILES_TOTAL = 12;
const MAX_INCOMING_RESERVED_BYTES = 100 * 1024 * 1024;
const MAX_INCOMING_BUFFERED_BYTES = 64 * 1024 * 1024;
const DISPLAY_IMAGE_MIME_RE = /^image\/(?:png|jpeg|jpg|gif|webp|avif|bmp)$/u;
const EMOJI_CATEGORIES: EmojiCategory[] = [
  { group: 0, icon: "😀", label: "表情" },
  { group: 1, icon: "👋", label: "人物" },
  { group: 3, icon: "🌿", label: "自然" },
  { group: 4, icon: "🍜", label: "食物" },
  { group: 5, icon: "✈️", label: "旅行" },
  { group: 6, icon: "⚽", label: "活动" },
  { group: 7, icon: "💡", label: "物品" },
  { group: 8, icon: "❤️", label: "符号" },
  { group: 9, icon: "🏳️", label: "旗帜" }
];
const EMOJI_GRID_LIMIT = 160;
let emojiDataPromise: Promise<EmojiRecord[]> | null = null;

function isTrustedContext(): boolean {
  return (
    window.isSecureContext ||
    window.location.hostname === "127.0.0.1" ||
    window.location.hostname === "localhost" ||
    window.location.hostname === "::1"
  );
}

function notificationPermission(): NotificationPermission | "unsupported" {
  return "Notification" in window ? Notification.permission : "unsupported";
}

function isWindowActive(): boolean {
  return document.visibilityState === "visible" && document.hasFocus();
}

async function requestDesktopNotificationPermission(): Promise<NotificationPermission | "unsupported"> {
  if (!("Notification" in window)) {
    return "unsupported";
  }
  if (Notification.permission === "default") {
    return Notification.requestPermission();
  }
  return Notification.permission;
}

async function unlockNotificationSound(): Promise<boolean> {
  const audioWindow = window as Window & { webkitAudioContext?: typeof AudioContext };
  const AudioContextCtor = window.AudioContext ?? audioWindow.webkitAudioContext;
  if (!AudioContextCtor) {
    return false;
  }
  notificationAudioContext ??= new AudioContextCtor();
  if (notificationAudioContext.state === "suspended") {
    await notificationAudioContext.resume();
  }
  return notificationAudioContext.state === "running";
}

function playNotificationSound(): void {
  const context = notificationAudioContext;
  if (!context || context.state !== "running") {
    return;
  }
  const now = context.currentTime;
  const oscillator = context.createOscillator();
  const gain = context.createGain();
  oscillator.type = "sine";
  oscillator.frequency.setValueAtTime(740, now);
  oscillator.frequency.exponentialRampToValueAtTime(520, now + 0.16);
  gain.gain.setValueAtTime(0.0001, now);
  gain.gain.exponentialRampToValueAtTime(0.055, now + 0.015);
  gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.18);
  oscillator.connect(gain);
  gain.connect(context.destination);
  oscillator.start(now);
  oscillator.stop(now + 0.2);
}

function makePassphrase(): string {
  return (
    base64urlEncode(randomBytes(18))
      .match(/.{1,6}/gu)
      ?.join("-") ?? base64urlEncode(randomBytes(18))
  );
}

const RANDOM_ADJECTIVES = [
  "amber",
  "bright",
  "calm",
  "clear",
  "fresh",
  "green",
  "quiet",
  "silver",
  "swift",
  "violet"
];
const RANDOM_NOUNS = [
  "atlas",
  "bridge",
  "harbor",
  "lantern",
  "meadow",
  "orbit",
  "ridge",
  "signal",
  "stone",
  "wave"
];

function randomItem(items: readonly string[]): string {
  return items[randomBytes(1)[0]! % items.length]!;
}

function randomLabel(prefix: string): string {
  const digitBytes = randomBytes(2);
  const digits = String((digitBytes[0]! * 256 + digitBytes[1]!) % 1000).padStart(3, "0");
  return `${prefix}-${randomItem(RANDOM_ADJECTIVES)}-${randomItem(RANDOM_NOUNS)}-${digits}`;
}

function avatarText(name: string): string {
  const cleaned = name.trim();
  return (cleaned[0] ?? "?").toUpperCase();
}

function insertTextAtCursor(input: HTMLTextAreaElement, value: string): void {
  input.setRangeText(value, input.selectionStart, input.selectionEnd, "end");
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.focus();
}

function formatBytes(size: number): string {
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function isDisplayImage(file: Blob): boolean {
  return DISPLAY_IMAGE_MIME_RE.test(file.type);
}

function mimeOrFallback(value: string): string {
  return value.trim().slice(0, 120) || "application/octet-stream";
}

function fileNameOrFallback(file: File): string {
  return file.name.trim().slice(0, 180) || "attachment.bin";
}

function incomingFileKey(from: string, fileId: string): string {
  return `${from}:${fileId}`;
}

function revokeMessageResources(message: ChatMessage): void {
  if (message.imageUrl) {
    URL.revokeObjectURL(message.imageUrl);
  }
}

function imageUrlFromBytes(bytes: Uint8Array, mime: string): string {
  return URL.createObjectURL(new Blob([asBufferSource(bytes)], { type: mime }));
}

function arrayBufferToBytes(buffer: ArrayBuffer): Uint8Array {
  return new Uint8Array(buffer);
}

function tryBase64urlDecode(value: string): Uint8Array | null {
  try {
    return base64urlDecode(value);
  } catch {
    return null;
  }
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", asBufferSource(bytes)));
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    window.setTimeout(resolve, ms);
  });
}

async function loadEmojiData(): Promise<EmojiRecord[]> {
  if (!emojiDataPromise) {
    emojiDataPromise = fetch(emojiDataUrl, {
      cache: "force-cache",
      credentials: "same-origin"
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error("emoji_data_unavailable");
        }
        return response.json() as Promise<EmojiRecord[]>;
      })
      .then((records) =>
        records
          .filter((record) => typeof record.emoji === "string" && record.emoji.length > 0)
          .sort((left, right) => left.order - right.order)
      )
      .catch((error: unknown) => {
        emojiDataPromise = null;
        throw error;
      });
  }
  return emojiDataPromise;
}

function emojiMatches(record: EmojiRecord, query: string): boolean {
  if (!query) {
    return true;
  }
  const haystack = [record.annotation, record.emoticon, ...(record.tags ?? [])]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(query.toLowerCase());
}

function parseInviteInput(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error("缺少邀请");
  }
  try {
    const url = new URL(trimmed);
    const params = new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash);
    const invite = params.get("invite");
    if (invite) {
      return invite;
    }
  } catch {
    // Not a URL; fall through to token parsing.
  }
  if (trimmed.includes("invite=")) {
    const params = new URLSearchParams(trimmed.replace(/^#/u, ""));
    const invite = params.get("invite");
    if (invite) {
      return invite;
    }
  }
  return trimmed;
}

function setApp(node: Node): void {
  removeChildren(appRoot);
  appRoot.append(node);
}

function pushMessage(state: Runtime, message: ChatMessage): void {
  state.messages.push(message);
  if (state.messages.length > MAX_RENDERED_MESSAGES) {
    const removed = state.messages.splice(0, state.messages.length - MAX_RENDERED_MESSAGES);
    for (const oldMessage of removed) {
      revokeMessageResources(oldMessage);
    }
  }
}

function unreadLabel(count: number): string {
  return count > 99 ? "99+" : String(count);
}

function markIncomingUnread(state: Runtime, message: ChatMessage, fromClientId: string): void {
  if (message.own) {
    return;
  }
  if (message.scope === "room") {
    if (state.privatePeerId) {
      state.roomUnread = Math.min(999, state.roomUnread + 1);
    }
    return;
  }
  if (state.privatePeerId !== fromClientId) {
    const current = state.privateUnread.get(fromClientId) ?? 0;
    state.privateUnread.set(fromClientId, Math.min(999, current + 1));
  }
}

function destroyPeer(peer: PeerRuntime): void {
  peer.sendRatchet.destroy();
  peer.recvRatchet.destroy();
  zeroize(peer.pair.rootKey);
  zeroize(peer.pair.sendCK);
  zeroize(peer.pair.recvCK);
}

function destroyRuntime(): void {
  const state = runtime;
  if (!state) {
    return;
  }
  state.ws.close();
  for (const peer of state.peers.values()) {
    destroyPeer(peer);
  }
  zeroize(state.room.roomSeed);
  zeroize(state.room.roomSecret);
  zeroize(state.room.roomPsk);
  zeroize(state.room.rosterKey);
  zeroize(state.room.fileKey);
  state.peers.clear();
  state.pendingRelays.clear();
  for (const key of [...state.incomingFiles.keys()]) {
    deleteIncomingFile(state, key);
  }
  for (const message of state.messages) {
    revokeMessageResources(message);
  }
  state.messages.splice(0);
  runtime = null;
}

function queuePendingRelay(state: Runtime, envelope: RelayEnvelope): void {
  const queued = state.pendingRelays.get(envelope.from) ?? [];
  queued.push(envelope);
  if (queued.length > MAX_PENDING_RELAYS_PER_PEER) {
    queued.splice(0, queued.length - MAX_PENDING_RELAYS_PER_PEER);
  }
  state.pendingRelays.set(envelope.from, queued);
}

async function processPendingRelays(): Promise<void> {
  const state = runtime;
  if (!state) {
    return;
  }
  for (const [clientId, queued] of [...state.pendingRelays.entries()]) {
    if (!state.peers.has(clientId)) {
      continue;
    }
    state.pendingRelays.delete(clientId);
    for (const envelope of queued) {
      await handleRelay(envelope, false);
    }
  }
}

function acceptPeerRate(peer: PeerRuntime): boolean {
  const now = Date.now();
  peer.messageWindow = peer.messageWindow.filter((seen) => now - seen < PEER_MESSAGE_WINDOW_MS);
  peer.messageWindow.push(now);
  return peer.messageWindow.length <= PEER_MAX_MESSAGES_PER_WINDOW;
}

function zeroizeIncomingFile(file: IncomingFile): void {
  for (const part of file.parts) {
    if (part) {
      zeroize(part);
    }
  }
  file.parts.length = 0;
  file.received = 0;
  file.receivedBytes = 0;
}

function deleteIncomingFile(state: Runtime, key: string): void {
  const file = state.incomingFiles.get(key);
  if (file) {
    zeroizeIncomingFile(file);
    state.incomingFiles.delete(key);
  }
}

function pruneIncomingFiles(state: Runtime): void {
  const now = Date.now();
  for (const [key, file] of state.incomingFiles) {
    if (now - file.startedAt > FILE_RECEIVE_TIMEOUT_MS) {
      deleteIncomingFile(state, key);
    }
  }
}

function incomingFileStats(state: Runtime, peerId?: string): { files: number; reservedBytes: number; bufferedBytes: number } {
  let files = 0;
  let reservedBytes = 0;
  let bufferedBytes = 0;
  for (const file of state.incomingFiles.values()) {
    if (!peerId || file.from === peerId) {
      files += 1;
      reservedBytes += file.size;
      bufferedBytes += file.receivedBytes;
    }
  }
  return { files, reservedBytes, bufferedBytes };
}

function setNotice(container: HTMLElement, message: string, isError = false): void {
  removeChildren(container);
  if (message) {
    container.append(el("div", { className: isError ? "warning" : "subtle", text: message }));
  }
}

function inviteUrl(inviteToken: string): string {
  return `${window.location.origin}${window.location.pathname}#invite=${inviteToken}`;
}

function renderLogin(): void {
  destroyRuntime();

  let mode: "single-link" | "two-channel" = "two-channel";
  let decodedInvite: ParsedInvite | null = null;
  if (pendingInviteToken) {
    try {
      decodedInvite = decodeInvite(pendingInviteToken);
    } catch {
      decodedInvite = null;
    }
  }

  const screen = el("section", { className: "login-screen" });
  const panel = el("div", { className: "login-panel" });
  const brand = el("div", { className: "brand" }, [
    el("span", { className: "brand-mark", text: "S" }),
    APP_NAME
  ]);
  const desc = decodedInvite
    ? el("p", { className: "subtle", text: "输入口令后即可进入。" })
    : null;
  const form = el("div", { className: "form-grid" });
  const notice = el("div");

  const nameInput = el("input", {
    type: "text",
    placeholder: "例如 Alice",
    value: randomLabel(decodedInvite ? "guest" : "user")
  });
  const randomName = el("button", {
    className: "icon-button",
    text: "⚄",
    title: "随机昵称",
    ariaLabel: "随机昵称"
  });
  randomName.addEventListener("click", () => {
    nameInput.value = randomLabel(decodedInvite ? "guest" : "user");
  });
  const roomInput = el("input", {
    type: "text",
    placeholder: "只在本机显示"
  });
  const randomRoom = el("button", {
    className: "icon-button",
    text: "⚄",
    title: "随机房间名",
    ariaLabel: "随机房间名"
  });
  randomRoom.addEventListener("click", () => {
    roomInput.value = randomLabel("room");
  });
  const inviteInput = el("textarea", {
    placeholder: "粘贴邀请链接或 invite token"
  });
  if (pendingInviteToken) {
    inviteInput.value = pendingInviteToken;
  }
  const passInput = el("input", {
    type: "password",
    placeholder:
      decodedInvite?.mode === "two-channel" ? "输入另一渠道收到的口令" : "创建时留空自动生成"
  });

  const modeButtons = el("div", { className: "segmented" });
  const highButton = el("button", { text: "私密" });
  const normalButton = el("button", { text: "公开" });
  highButton.classList.add("active");
  highButton.addEventListener("click", () => {
    mode = "two-channel";
    highButton.classList.add("active");
    normalButton.classList.remove("active");
    passInput.disabled = false;
    passInput.placeholder = "留空自动生成口令";
  });
  normalButton.addEventListener("click", () => {
    mode = "single-link";
    normalButton.classList.add("active");
    highButton.classList.remove("active");
    passInput.disabled = true;
    passInput.value = "";
  });
  modeButtons.append(highButton, normalButton);

  form.append(
    el("label", { className: "field" }, [
      "昵称",
      el("div", { className: "input-row" }, [nameInput, randomName])
    ])
  );
  if (!decodedInvite) {
    form.append(
      el("label", { className: "field" }, [
        "房间显示名",
        el("div", { className: "input-row" }, [roomInput, randomRoom])
      ])
    );
  }

  if (decodedInvite) {
    form.append(el("label", { className: "field" }, ["邀请", inviteInput]));
    if (decodedInvite.mode === "two-channel") {
      form.append(el("label", { className: "field" }, ["独立口令", passInput]));
    }
  } else {
    form.append(
      el("label", { className: "field" }, ["隐私性", modeButtons]),
      el("label", { className: "field" }, ["口令", passInput])
    );
  }

  const action = el("button", {
    className: "primary",
    text: decodedInvite ? "加入房间" : "创建房间"
  });
  action.disabled = !isTrustedContext();
  action.addEventListener("click", () => {
    void (async () => {
      try {
        setNotice(notice, "");
        action.disabled = true;
        const displayName = nameInput.value.trim().slice(0, 40) || "访客";
        const roomName = roomInput.value.trim().slice(0, 60) || "临时房间";
        if (decodedInvite || inviteInput.value.trim()) {
          const inviteToken = parseInviteInput(inviteInput.value || pendingInviteToken || "");
          const invite = decodeInvite(inviteToken);
          const secret = await inviteToSecret(
            invite,
            invite.mode === "two-channel" ? passInput.value : undefined
          );
          await startRoom({ secret, roomName, displayName, mode: invite.mode });
          return;
        }
        const secret = createInviteSecret();
        let shareToken: string;
        let generatedPassphrase = "";
        if (mode === "two-channel") {
          generatedPassphrase = passInput.value.trim() || makePassphrase();
          shareToken = encodeInvite(await wrapInviteSecret(secret, generatedPassphrase));
        } else {
          shareToken = encodeInvite(createSingleLinkInvite(secret));
        }
        const link = inviteUrl(shareToken);
        await startRoom({
          secret,
          roomName,
          displayName,
          mode,
          inviteLink: link,
          invitePassphrase: generatedPassphrase
        });
        showInviteDialog(link, generatedPassphrase, mode);
      } catch (error) {
        setNotice(notice, error instanceof Error ? error.message : "操作失败", true);
        action.disabled = false;
      }
    })();
  });

  form.append(action, notice);
  if (!isTrustedContext()) {
    form.append(
      el("div", {
        className: "warning",
        text: "当前页面不是 HTTPS，也不是 localhost，已禁用生产聊天入口。"
      })
    );
  }
  if (decodedInvite?.mode === "single-link") {
    form.append(
      el("div", { className: "warning", text: "该邀请为单链接模式，链接包含全部进入秘密。" })
    );
  }

  panel.append(brand);
  if (desc) {
    panel.append(desc);
  }
  panel.append(form);
  screen.append(panel);
  setApp(screen);
}

async function startRoom(input: {
  secret: InviteSecret;
  roomName: string;
  displayName: string;
  mode: "single-link" | "two-channel";
  inviteLink?: string;
  invitePassphrase?: string;
}): Promise<void> {
  const room = await deriveRoomSecrets(input.secret);
  const session = await generateSessionKeys();
  const clientId = base64urlEncode(randomBytes(16));
  const capabilities: CapabilitySet = {
    ratchet: "v1",
    aead: "aes-gcm",
    file: true,
    maxRelayBytes: 8 * 1024 * 1024
  };
  const joinMessage: JoinMessage = {
    v: 3,
    t: "join",
    roomId: room.roomId,
    clientId,
    sessionPub: session.publicKeyToken,
    capabilities
  };
  const ws = new WsClient(wsUrlForRoom(room.roomId), joinMessage, {
    open: () => {
      void sendProfilesToAll();
    },
    close: () => {
      if (runtime) {
        runtime.status = "已断开";
        renderChat();
      }
    },
    status: (status) => {
      if (runtime) {
        runtime.status = status;
        renderChat();
      }
    },
    message: (message) => {
      void handleServerMessage(message);
    }
  });
  runtime = {
    roomName: input.roomName,
    displayName: input.displayName,
    mode: input.mode,
    room,
    clientId,
    session,
    capabilities,
    ws,
    peers: new Map(),
    pendingRelays: new Map(),
    incomingFiles: new Map(),
    members: [],
    messages: [],
    status: "连接中",
    safetyCode: "计算中",
    privatePeerId: null,
    roomUnread: 0,
    privateUnread: new Map(),
    inviteLink: input.inviteLink ?? null,
    invitePassphrase: input.invitePassphrase ?? "",
    inviteMode: input.mode,
    notificationsEnabled: notificationPermission() === "granted",
    soundEnabled: false,
    lastNotificationAt: 0
  };
  renderChat();
  ws.connect();
}

async function handleServerMessage(message: ServerMessage): Promise<void> {
  const state = runtime;
  if (!state) {
    return;
  }
  if (message.t === "members") {
    await handleMembers(message);
    return;
  }
  if (message.t === "relay") {
    await handleRelay(message);
  }
}

async function handleMembers(message: MembersMessage): Promise<void> {
  const state = runtime;
  if (!state || message.roomId !== state.room.roomId) {
    return;
  }
  state.members = message.members;
  const liveIds = new Set(message.members.map((member) => member.clientId));
  for (const [clientId, peer] of state.peers) {
    if (!liveIds.has(clientId)) {
      destroyPeer(peer);
      state.peers.delete(clientId);
      state.pendingRelays.delete(clientId);
      state.privateUnread.delete(clientId);
    }
  }
  if (state.privatePeerId && !state.peers.has(state.privatePeerId)) {
    state.privatePeerId = null;
  }
  for (const member of message.members) {
    if (member.clientId === state.clientId) {
      continue;
    }
    const existing = state.peers.get(member.clientId);
    if (existing && existing.sessionPub === member.sessionPub) {
      continue;
    }
    if (existing && existing.sessionPub !== member.sessionPub) {
      addSystemMessage(`${existing.displayName} 的会话密钥已更新。`);
    }
    if (existing) {
      destroyPeer(existing);
    }
    const pair = await derivePairSession({
      roomId: state.room.roomId,
      roomPsk: state.room.roomPsk,
      localPrivateKey: state.session.privateKey,
      localClientId: state.clientId,
      localSessionPub: state.session.publicKeyToken,
      peerClientId: member.clientId,
      peerSessionPub: member.sessionPub,
      capabilities: state.capabilities
    });
    const sendRatchet = new SendRatchet(pair.sendCK);
    const recvRatchet = new ReceiveRatchet(pair.recvCK);
    zeroize(pair.sendCK);
    zeroize(pair.recvCK);
    state.peers.set(member.clientId, {
      clientId: member.clientId,
      sessionPub: member.sessionPub,
      displayName: existing?.displayName ?? `临时成员 ${member.clientId.slice(0, 4)}`,
      capabilities: member.capabilities,
      pair,
      sendRatchet,
      recvRatchet,
      fingerprint: await peerFingerprint(state.room.roomId, member.sessionPub),
      profileSent: false,
      messageWindow: existing?.messageWindow ?? [],
      decryptFailures: 0,
      lastFailureNoticeAt: 0
    });
  }
  const digest = await rosterDigest(message.members);
  state.safetyCode = await roomSafetyCode(state.room.rosterKey, digest);
  await processPendingRelays();
  renderChat();
  await sendProfilesToAll();
}

async function sendProfilesToAll(): Promise<void> {
  const state = runtime;
  if (!state) {
    return;
  }
  for (const peer of state.peers.values()) {
    if (peer.profileSent) {
      continue;
    }
    const payload: PlainPayload = {
      type: "profile",
      displayName: state.displayName,
      avatarSeed: state.clientId,
      createdAt: Date.now()
    };
    const envelope = await sealPayload({
      roomId: state.room.roomId,
      from: state.clientId,
      to: peer.clientId,
      kind: "profile",
      transcriptHash: peer.pair.transcriptHash,
      ratchet: peer.sendRatchet,
      payload
    });
    peer.profileSent = state.ws.send(envelope);
  }
}

async function handleRelay(envelope: RelayEnvelope, allowQueue = true): Promise<void> {
  const state = runtime;
  if (!state) {
    return;
  }
  const valid = validateRelayEnvelope(
    envelope,
    state.room.roomId,
    undefined,
    (clientId) => clientId === state.clientId
  );
  if (!valid || envelope.to !== state.clientId) {
    return;
  }
  const peer = state.peers.get(envelope.from);
  if (!peer) {
    if (allowQueue) {
      queuePendingRelay(state, envelope);
    }
    return;
  }
  if (!acceptPeerRate(peer)) {
    return;
  }
  const payload = await openPayload(envelope, peer.pair.transcriptHash, peer.recvRatchet);
  if (!payload) {
    peer.decryptFailures += 1;
    const now = Date.now();
    if (now - peer.lastFailureNoticeAt > FAILURE_NOTICE_INTERVAL_MS) {
      addSystemMessage(`${peer.displayName} 有密文未通过验证，已丢弃。`);
      peer.lastFailureNoticeAt = now;
    }
    return;
  }
  if (payload.type === "profile") {
    peer.displayName = payload.displayName.slice(0, 40) || peer.displayName;
    renderChat();
    return;
  }
  await handlePlainPayload(state, envelope, peer, payload, "room");
}

async function handlePlainPayload(
  state: Runtime,
  envelope: RelayEnvelope,
  peer: PeerRuntime,
  payload: PlainPayload,
  scope: "room" | "private"
): Promise<void> {
  if (payload.type === "private") {
    await handlePlainPayload(state, envelope, peer, payload.inner, "private");
    return;
  }
  if (payload.type === "text") {
    const message: ChatMessage = {
      id: `${envelope.from}:${envelope.seq}`,
      own: false,
      author: peer.displayName,
      kind: "text",
      text: payload.text,
      createdAt: payload.createdAt,
      scope
    };
    if (scope === "private") {
      message.peerName = peer.displayName;
    }
    pushMessage(state, message);
    markIncomingUnread(state, message, peer.clientId);
    renderChat();
    notifyIncomingMessage(state, message);
    return;
  }
  if (payload.type === "image") {
    if (!DISPLAY_IMAGE_MIME_RE.test(payload.mime)) {
      return;
    }
    const bytes = tryBase64urlDecode(payload.bytes);
    if (!bytes) {
      return;
    }
    if (bytes.length > MAX_INLINE_IMAGE_BYTES) {
      addSystemMessage(`${peer.displayName} 发送的图片超过本机预览限制，已丢弃。`);
      return;
    }
    const message: ChatMessage = {
      id: `${envelope.from}:${envelope.seq}`,
      own: false,
      author: peer.displayName,
      kind: "image",
      imageUrl: imageUrlFromBytes(bytes, payload.mime),
      imageMime: payload.mime,
      createdAt: payload.createdAt,
      scope
    };
    if (scope === "private") {
      message.peerName = peer.displayName;
    }
    pushMessage(state, message);
    markIncomingUnread(state, message, peer.clientId);
    renderChat();
    notifyIncomingMessage(state, message);
    return;
  }
  if (payload.type === "file-meta") {
    handleFileMeta(state, peer, payload, scope);
    return;
  }
  if (payload.type === "file-chunk") {
    handleFileChunk(state, envelope.from, payload);
    return;
  }
  if (payload.type === "file-done") {
    await handleFileDone(state, envelope.from, payload);
  }
}

function handleFileMeta(
  state: Runtime,
  peer: PeerRuntime,
  payload: Extract<PlainPayload, { type: "file-meta" }>,
  scope: "room" | "private"
): void {
  pruneIncomingFiles(state);
  const key = incomingFileKey(peer.clientId, payload.fileId);
  deleteIncomingFile(state, key);
  if (
    payload.size > MAX_FILE_BYTES ||
    payload.chunks > Math.ceil(Math.max(payload.size, 1) / FILE_CHUNK_BYTES)
  ) {
    addSystemMessage(`${peer.displayName} 发送的文件超过限制，已拒绝接收。`);
    return;
  }
  const peerStats = incomingFileStats(state, peer.clientId);
  const totalStats = incomingFileStats(state);
  if (
    peerStats.files >= MAX_INCOMING_FILES_PER_PEER ||
    totalStats.files >= MAX_INCOMING_FILES_TOTAL ||
    totalStats.reservedBytes + payload.size > MAX_INCOMING_RESERVED_BYTES
  ) {
    addSystemMessage(`${peer.displayName} 发送的文件超过本机接收队列限制，已拒绝接收。`);
    return;
  }
  const incoming: IncomingFile = {
    fileId: payload.fileId,
    from: peer.clientId,
    author: peer.displayName,
    scope,
    name: payload.name.slice(0, 180),
    mime: mimeOrFallback(payload.mime),
    size: payload.size,
    chunks: payload.chunks,
    createdAt: payload.createdAt,
    parts: new Array<Uint8Array | undefined>(payload.chunks),
    received: 0,
    receivedBytes: 0,
    startedAt: Date.now()
  };
  if (scope === "private") {
    incoming.peerName = peer.displayName;
  }
  state.incomingFiles.set(key, incoming);
}

function handleFileChunk(
  state: Runtime,
  from: string,
  payload: Extract<PlainPayload, { type: "file-chunk" }>
): void {
  pruneIncomingFiles(state);
  const incoming = state.incomingFiles.get(incomingFileKey(from, payload.fileId));
  if (!incoming || payload.total !== incoming.chunks || incoming.parts[payload.index]) {
    return;
  }
  const bytes = tryBase64urlDecode(payload.bytes);
  if (!bytes) {
    deleteIncomingFile(state, incomingFileKey(from, payload.fileId));
    return;
  }
  const totalStats = incomingFileStats(state);
  if (
    bytes.length > FILE_CHUNK_BYTES ||
    incoming.receivedBytes + bytes.length > incoming.size ||
    totalStats.bufferedBytes + bytes.length > MAX_INCOMING_BUFFERED_BYTES
  ) {
    zeroize(bytes);
    deleteIncomingFile(state, incomingFileKey(from, payload.fileId));
    return;
  }
  incoming.parts[payload.index] = bytes;
  incoming.received += 1;
  incoming.receivedBytes += bytes.length;
}

async function handleFileDone(
  state: Runtime,
  from: string,
  payload: Extract<PlainPayload, { type: "file-done" }>
): Promise<void> {
  pruneIncomingFiles(state);
  const key = incomingFileKey(from, payload.fileId);
  const incoming = state.incomingFiles.get(key);
  if (!incoming || incoming.received !== incoming.chunks) {
    return;
  }
  const parts = incoming.parts.filter((part): part is Uint8Array => part !== undefined);
  if (parts.length !== incoming.chunks) {
    return;
  }
  const bytes = concatBytes(...parts);
  const digest = await sha256(bytes);
  if (bytes.length !== incoming.size || base64urlEncode(digest) !== payload.sha256) {
    zeroize(bytes);
    zeroize(digest);
    deleteIncomingFile(state, key);
    addSystemMessage(`${incoming.author} 发送的文件完整性校验失败，已丢弃。`);
    return;
  }
  const blob = new Blob([asBufferSource(bytes)], { type: incoming.mime });
  zeroize(bytes);
  zeroize(digest);
  const message: ChatMessage = {
    id: `${from}:file:${payload.fileId}`,
    own: false,
    author: incoming.author,
    kind: "file",
    text: incoming.name,
    fileName: incoming.name,
    fileSize: incoming.size,
    fileBlob: blob,
    createdAt: incoming.createdAt,
    scope: incoming.scope
  };
  if (incoming.peerName) {
    message.peerName = incoming.peerName;
  }
  deleteIncomingFile(state, key);
  pushMessage(state, message);
  markIncomingUnread(state, message, from);
  renderChat();
  notifyIncomingMessage(state, message);
}

function addSystemMessage(text: string): void {
  const state = runtime;
  if (!state) {
    return;
  }
  pushMessage(state, {
    id: `system:${Date.now()}:${Math.random()}`,
    own: false,
    author: "系统",
    kind: "text",
    text,
    createdAt: Date.now(),
    scope: "room"
  });
  renderChat();
}

async function enableRoomNotifications(): Promise<void> {
  const state = runtime;
  if (!state) {
    return;
  }
  const permission = await requestDesktopNotificationPermission();
  const soundReady = await unlockNotificationSound();
  state.notificationsEnabled = permission === "granted";
  state.soundEnabled = soundReady;
  if (state.notificationsEnabled && state.soundEnabled) {
    addSystemMessage("桌面通知和声音提示已开启。");
  } else if (state.notificationsEnabled) {
    addSystemMessage("桌面通知已开启，当前浏览器不支持声音提示。");
  } else if (state.soundEnabled) {
    addSystemMessage(
      permission === "denied" ? "浏览器通知已被拒绝，声音提示已开启。" : "声音提示已开启。"
    );
  } else {
    addSystemMessage("当前浏览器无法开启通知或声音提示。");
  }
}

function notificationButtonText(state: Runtime): string {
  if (state.notificationsEnabled && state.soundEnabled) {
    return "通知已开";
  }
  if (state.notificationsEnabled) {
    return "打开声音";
  }
  if (state.soundEnabled) {
    return "声音已开";
  }
  if (notificationPermission() === "denied") {
    return "打开声音";
  }
  return "打开通知";
}

function notifyIncomingMessage(state: Runtime, message: ChatMessage): void {
  const now = Date.now();
  if (now - state.lastNotificationAt < NOTIFICATION_THROTTLE_MS) {
    return;
  }
  state.lastNotificationAt = now;
  if (state.soundEnabled) {
    playNotificationSound();
  }
  if (!state.notificationsEnabled || notificationPermission() !== "granted" || isWindowActive()) {
    return;
  }
  const scope = message.scope === "private" ? "私聊" : "房间";
  const title =
    message.scope === "private" ? `${message.author} 发来私聊消息` : `${message.author} 发来房间消息`;
  const kindText = message.kind === "image" ? "图片消息" : message.kind === "file" ? "文件消息" : "文本消息";
  const notification = new Notification(title, {
    body: `收到一条${scope}${kindText}`,
    tag: `${state.room.roomId}:${message.scope}`,
    renotify: false
  });
  notification.addEventListener("click", () => {
    window.focus();
    notification.close();
  });
}

function currentDeliveryContext(state: Runtime): DeliveryContext {
  const targetPeer = state.privatePeerId ? state.peers.get(state.privatePeerId) : null;
  const context: DeliveryContext = {
    targets: targetPeer ? [targetPeer] : [...state.peers.values()],
    scope: targetPeer ? "private" : "room"
  };
  if (targetPeer) {
    context.peerName = targetPeer.displayName;
  }
  return context;
}

async function sendPayloadWithContext(
  state: Runtime,
  delivery: DeliveryContext,
  payload: PlainPayload,
  kind: RelayKind
): Promise<void> {
  const outboundPayload: PlainPayload =
    delivery.scope === "private" ? { type: "private", inner: payload } : payload;
  const relayKind: RelayKind = delivery.scope === "private" ? "private" : kind;
  for (const peer of delivery.targets) {
    const envelope = await sealPayload({
      roomId: state.room.roomId,
      from: state.clientId,
      to: peer.clientId,
      kind: relayKind,
      transcriptHash: peer.pair.transcriptHash,
      ratchet: peer.sendRatchet,
      payload: outboundPayload
    });
    state.ws.send(envelope);
  }
}

async function sendTextMessage(text: string): Promise<void> {
  const state = runtime;
  const message = text.trim();
  if (!state || !message) {
    return;
  }
  const delivery = currentDeliveryContext(state);
  const textPayload: PlainPayload = {
    type: "text",
    text: message.slice(0, 8_000),
    createdAt: Date.now()
  };
  const ownMessage: ChatMessage = {
    id: `own:${Date.now()}`,
    own: true,
    author: state.displayName,
    kind: "text",
    text: textPayload.text,
    createdAt: textPayload.createdAt,
    scope: delivery.scope
  };
  if (delivery.peerName) {
    ownMessage.peerName = delivery.peerName;
  }
  await sendPayloadWithContext(state, delivery, textPayload, "text");
  pushMessage(state, ownMessage);
  renderChat();
}

async function sendImageBlob(blob: Blob, fallbackName: string): Promise<void> {
  const state = runtime;
  if (!state) {
    return;
  }
  if (!isDisplayImage(blob)) {
    addSystemMessage("仅支持 PNG、JPEG、GIF、WebP、AVIF、BMP 图片直接预览。");
    return;
  }
  if (blob.size > MAX_INLINE_IMAGE_BYTES) {
    addSystemMessage(`图片超过 ${formatBytes(MAX_INLINE_IMAGE_BYTES)}，请作为文件附件发送。`);
    return;
  }
  const delivery = currentDeliveryContext(state);
  const bytes = arrayBufferToBytes(await blob.arrayBuffer());
  const createdAt = Date.now();
  const imageUrl = imageUrlFromBytes(bytes, blob.type);
  const ownMessage: ChatMessage = {
    id: `own:image:${createdAt}:${Math.random()}`,
    own: true,
    author: state.displayName,
    kind: "image",
    text: fallbackName,
    imageUrl,
    imageMime: blob.type,
    createdAt,
    scope: delivery.scope
  };
  if (delivery.peerName) {
    ownMessage.peerName = delivery.peerName;
  }
  try {
    await sendPayloadWithContext(
      state,
      delivery,
      {
        type: "image",
        mime: blob.type,
        bytes: base64urlEncode(bytes),
        createdAt
      },
      "image"
    );
    pushMessage(state, ownMessage);
    renderChat();
  } catch (error) {
    revokeMessageResources(ownMessage);
    addSystemMessage(error instanceof Error ? "图片发送失败。" : "图片发送失败。");
  }
}

async function sendAttachmentFile(file: File): Promise<void> {
  const state = runtime;
  if (!state) {
    return;
  }
  if (file.size > MAX_FILE_BYTES) {
    addSystemMessage(`${file.name || "文件"} 超过 ${formatBytes(MAX_FILE_BYTES)}，已拒绝发送。`);
    return;
  }
  const delivery = currentDeliveryContext(state);
  const bytes = arrayBufferToBytes(await file.arrayBuffer());
  const createdAt = Date.now();
  const fileId = base64urlEncode(randomBytes(16));
  const chunks = Math.max(1, Math.ceil(bytes.length / FILE_CHUNK_BYTES));
  const name = fileNameOrFallback(file);
  const mime = mimeOrFallback(file.type);
  const digest = await sha256(bytes);
  await sendPayloadWithContext(
    state,
    delivery,
    {
      type: "file-meta",
      fileId,
      name,
      mime,
      size: bytes.length,
      chunks,
      createdAt
    },
    "file-meta"
  );
  const chunkDelayMs =
    delivery.targets.length > 0 ? Math.max(90, delivery.targets.length * 125) : 0;
  for (let index = 0; index < chunks; index += 1) {
    const start = index * FILE_CHUNK_BYTES;
    const chunk = bytes.subarray(start, Math.min(start + FILE_CHUNK_BYTES, bytes.length));
    await sendPayloadWithContext(
      state,
      delivery,
      {
        type: "file-chunk",
        fileId,
        index,
        total: chunks,
        bytes: base64urlEncode(chunk)
      },
      "file-chunk"
    );
    if (chunkDelayMs > 0 && index < chunks - 1) {
      await delay(chunkDelayMs);
    }
  }
  await sendPayloadWithContext(
    state,
    delivery,
    {
      type: "file-done",
      fileId,
      sha256: base64urlEncode(digest)
    },
    "file-done"
  );
  const ownMessage: ChatMessage = {
    id: `own:file:${createdAt}:${Math.random()}`,
    own: true,
    author: state.displayName,
    kind: "file",
    text: name,
    fileName: name,
    fileSize: bytes.length,
    fileBlob: file,
    createdAt,
    scope: delivery.scope
  };
  if (delivery.peerName) {
    ownMessage.peerName = delivery.peerName;
  }
  pushMessage(state, ownMessage);
  renderChat();
}

async function sendFiles(files: readonly File[]): Promise<void> {
  const selected = files.slice(0, MAX_FILE_BATCH);
  if (files.length > MAX_FILE_BATCH) {
    addSystemMessage(`单次最多发送 ${MAX_FILE_BATCH} 个文件，已只处理前 ${MAX_FILE_BATCH} 个。`);
  }
  const totalSize = selected.reduce((sum, file) => sum + file.size, 0);
  if (totalSize > MAX_FILE_BATCH_BYTES) {
    addSystemMessage(`单批附件超过 ${formatBytes(MAX_FILE_BATCH_BYTES)}，已拒绝发送。`);
    return;
  }
  for (const file of selected) {
    try {
      if (isDisplayImage(file) && file.size <= MAX_INLINE_IMAGE_BYTES) {
        await sendImageBlob(file, fileNameOrFallback(file));
      } else {
        await sendAttachmentFile(file);
      }
    } catch {
      addSystemMessage(`${file.name || "附件"} 发送失败。`);
    }
  }
}

function renderChat(): void {
  const state = runtime;
  if (!state) {
    renderLogin();
    return;
  }
  const layout = el("section", { className: "chat-layout" });
  const sidebar = el("aside", { className: "sidebar" });
  const roomHead = el("div", { className: "room-head" });
  roomHead.append(
    el("div", { className: "room-title", text: state.roomName }),
    el("div", { className: "safety-line", text: `房间安全码 ${state.safetyCode}` }),
    el("div", {
      className: "safety-line",
      text: state.mode === "two-channel" ? "双通道邀请" : "单链接邀请"
    })
  );
  const memberList = el("div", { className: "member-list" });
  const self = el("button", {
    className: state.privatePeerId ? "member member-button" : "member member-button active",
    title: "切回房间",
    ariaLabel: "切回房间"
  });
  self.addEventListener("click", () => {
    state.privatePeerId = null;
    state.roomUnread = 0;
    renderChat();
  });
  const roomBadge =
    state.roomUnread > 0
      ? el("span", { className: "badge unread", text: unreadLabel(state.roomUnread) })
      : el("span", { className: "badge ok", text: "房间" });
  self.append(
    el("span", { className: "member-avatar", text: avatarText(state.roomName) }),
    el("span", { className: "member-content" }, [
      el("span", { className: "member-name" }, [state.roomName]),
      el("span", { className: "member-subtitle", text: "房间" })
    ]),
    roomBadge
  );
  memberList.append(self);
  for (const peer of state.peers.values()) {
    const isPrivateTarget = state.privatePeerId === peer.clientId;
    const item = el("button", {
      className: isPrivateTarget ? "member member-button active" : "member member-button",
      title: `私聊 ${peer.displayName}`,
      ariaLabel: `私聊 ${peer.displayName}`
    });
    setDataset(item, "clientId", peer.clientId);
    item.addEventListener("click", () => {
      state.privatePeerId = peer.clientId;
      state.privateUnread.delete(peer.clientId);
      renderChat();
    });
    const unread = state.privateUnread.get(peer.clientId) ?? 0;
    const badge = unread > 0
      ? el("span", { className: "badge unread", text: unreadLabel(unread) })
      : isPrivateTarget
      ? el("span", { className: "badge ok", text: "私聊" })
      : el("span", { className: "badge", text: "在线" });
    item.append(
      el("span", { className: "member-avatar", text: avatarText(peer.displayName) }),
      el("span", { className: "member-content" }, [
        el("span", { className: "member-name", text: peer.displayName }),
        el("span", {
          className: "member-subtitle",
          text: isPrivateTarget ? "当前私聊" : "点击私聊"
        })
      ]),
      badge
    );
    memberList.append(item);
  }
  sidebar.append(roomHead, memberList);

  const main = el("section", { className: "chat-main" });
  const topbar = el("header", { className: "topbar" });
  const privatePeer = state.privatePeerId ? state.peers.get(state.privatePeerId) : null;
  const modeText = privatePeer ? `私聊：${privatePeer.displayName}` : "房间";
  const status = el("div", { className: "chat-heading" }, [
    el("div", {
      className: "chat-heading-title",
      text: privatePeer ? privatePeer.displayName : state.roomName
    }),
    el("div", {
      className: "chat-heading-meta",
      text: `${state.status} · ${state.peers.size + 1} 人在线 · ${modeText}`
    })
  ]);
  const topbarButtons: Node[] = [];
  const notifications = el("button", {
    className: state.notificationsEnabled || state.soundEnabled ? "secondary active" : "secondary",
    text: notificationButtonText(state)
  });
  notifications.type = "button";
  notifications.addEventListener("click", () => {
    void enableRoomNotifications();
  });
  topbarButtons.push(notifications);
  if (state.inviteLink) {
    const invite = el("button", { className: "secondary", text: "邀请" });
    invite.addEventListener("click", () =>
      showInviteDialog(state.inviteLink!, state.invitePassphrase, state.inviteMode)
    );
    topbarButtons.push(invite);
  }
  const security = el("button", { className: "secondary", text: "安全详情" });
  security.addEventListener("click", showSecurityDetails);
  topbarButtons.push(security);
  const leave = el("button", { className: "secondary", text: "退出房间" });
  leave.addEventListener("click", () => {
    destroyRuntime();
    renderLogin();
  });
  topbarButtons.push(leave);
  topbar.append(status, el("div", { className: "topbar-actions" }, topbarButtons));

  const modeBanner = el("div", {
    className: privatePeer ? "mode-banner private" : "mode-banner room",
    text: privatePeer
      ? `私聊模式：消息只发送给 ${privatePeer.displayName}`
      : "房间模式：消息会发送给所有在线成员"
  });

  const messages = el("div", { className: "messages" });
  for (const message of state.messages) {
    const row = el("article", {
      className: ["message", message.own ? "own" : "", message.scope].filter(Boolean).join(" ")
    });
    const scopeText =
      message.scope === "private"
        ? `私聊${message.peerName ? ` · ${message.peerName}` : ""}`
        : "房间";
    const metaText = `${message.author} · ${scopeText} · ${new Date(message.createdAt).toLocaleTimeString()}`;
    row.append(el("div", { className: "message-meta", text: metaText }));
    if (message.kind === "image" && message.imageUrl) {
      const image = el("img", {
        className: "message-image",
        title: message.text ?? "图片"
      });
      image.src = message.imageUrl;
      image.alt = message.text ?? "图片";
      image.tabIndex = 0;
      image.setAttribute("role", "button");
      image.addEventListener("click", () => showImageViewer(message.imageUrl!, image.alt));
      image.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          showImageViewer(message.imageUrl!, image.alt);
        }
      });
      row.append(image);
    } else if (message.kind === "file" && message.fileBlob) {
      const fileBox = el("div", { className: "file-message" });
      const fileInfo = el("div", { className: "file-info" }, [
        el("div", { className: "file-name", text: message.fileName ?? "附件" }),
        el("div", {
          className: "file-size",
          text: formatBytes(message.fileSize ?? message.fileBlob.size)
        })
      ]);
      const download = el("button", { className: "file-download", text: "下载" });
      download.type = "button";
      download.addEventListener("click", () => {
        safeDownload(message.fileBlob!, message.fileName ?? "attachment.bin");
      });
      fileBox.append(el("div", { className: "file-icon", text: "📎" }), fileInfo, download);
      row.append(fileBox);
    } else {
      row.append(el("div", { className: "message-text", text: message.text ?? "" }));
    }
    messages.append(row);
  }

  const composer = el("form", { className: "composer" });
  const composerPill = el("div", { className: "composer-pill" });
  const emojiWrap = el("div", { className: "emoji-wrap" });
  const emojiButton = el("button", {
    className: "icon-button emoji-button",
    text: "☺",
    title: "表情",
    ariaLabel: "表情"
  });
  emojiButton.type = "button";
  const emojiPanel = el("div", { className: "emoji-panel" });
  const emojiSearch = el("input", {
    className: "emoji-search",
    type: "search",
    placeholder: "搜索表情"
  });
  const emojiCategories = el("div", { className: "emoji-categories" });
  const emojiGrid = el("div", { className: "emoji-grid" });
  let selectedEmojiGroup = EMOJI_CATEGORIES[0]!.group;
  let emojiRecords: EmojiRecord[] | null = null;
  const input = el("textarea", {
    placeholder: "消息"
  });
  input.rows = 1;
  const syncInputHeight = () => {
    input.style.height = "auto";
    input.style.height = `${Math.min(input.scrollHeight, 112)}px`;
  };

  const renderEmojiCategories = () => {
    removeChildren(emojiCategories);
    for (const category of EMOJI_CATEGORIES) {
      const tab = el("button", {
        className: category.group === selectedEmojiGroup ? "emoji-tab active" : "emoji-tab",
        text: category.icon,
        title: category.label,
        ariaLabel: category.label
      });
      tab.type = "button";
      tab.addEventListener("click", () => {
        selectedEmojiGroup = category.group;
        emojiSearch.value = "";
        renderEmojiCategories();
        renderEmojiGrid();
      });
      emojiCategories.append(tab);
    }
  };

  const renderEmojiGrid = () => {
    removeChildren(emojiGrid);
    if (!emojiRecords) {
      emojiGrid.append(el("div", { className: "emoji-empty", text: "正在加载…" }));
      return;
    }
    const query = emojiSearch.value.trim();
    const visible = emojiRecords
      .filter((record) =>
        query ? emojiMatches(record, query) : record.group === selectedEmojiGroup
      )
      .slice(0, EMOJI_GRID_LIMIT);
    if (visible.length === 0) {
      emojiGrid.append(el("div", { className: "emoji-empty", text: "没有匹配的表情" }));
      return;
    }
    for (const record of visible) {
      const item = el("button", {
        className: "emoji-item",
        text: record.emoji,
        title: record.annotation,
        ariaLabel: `插入 ${record.annotation}`
      });
      item.type = "button";
      item.addEventListener("click", () => {
        insertTextAtCursor(input, record.emoji);
        emojiPanel.classList.remove("open");
      });
      emojiGrid.append(item);
    }
  };

  const ensureEmojiData = () => {
    renderEmojiGrid();
    if (emojiRecords) {
      return;
    }
    void loadEmojiData()
      .then((records) => {
        emojiRecords = records;
        renderEmojiGrid();
      })
      .catch(() => {
        removeChildren(emojiGrid);
        emojiGrid.append(el("div", { className: "emoji-empty", text: "表情数据加载失败" }));
      });
  };

  renderEmojiCategories();
  emojiPanel.append(emojiSearch, emojiCategories, emojiGrid);
  emojiSearch.addEventListener("input", renderEmojiGrid);
  emojiSearch.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
    }
  });
  emojiButton.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    emojiPanel.classList.toggle("open");
    if (emojiPanel.classList.contains("open")) {
      ensureEmojiData();
    }
  });
  emojiPanel.addEventListener("click", (event) => {
    event.stopPropagation();
  });
  composer.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      emojiPanel.classList.remove("open");
      input.focus();
    }
  });
  emojiWrap.append(emojiButton, emojiPanel);
  const attach = el("button", {
    className: "icon-button attach-button",
    text: "📎",
    title: "附件",
    ariaLabel: "附件"
  });
  attach.type = "button";
  const fileInput = el("input", { className: "file-input", type: "file" });
  fileInput.multiple = true;
  attach.addEventListener("click", () => {
    fileInput.click();
  });
  fileInput.addEventListener("change", () => {
    const selected = [...(fileInput.files ?? [])];
    fileInput.value = "";
    if (selected.length > 0) {
      void sendFiles(selected);
    }
  });
  const send = el("button", {
    className: "primary send-button",
    text: "➤",
    title: "发送",
    ariaLabel: "发送"
  });
  send.type = "submit";
  input.addEventListener("input", syncInputHeight);
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      send.click();
    }
  });
  input.addEventListener("paste", (event) => {
    const files = [...(event.clipboardData?.files ?? [])].filter((file) =>
      file.type.startsWith("image/")
    );
    if (files.length === 0) {
      return;
    }
    event.preventDefault();
    emojiPanel.classList.remove("open");
    for (const file of files.slice(0, MAX_FILE_BATCH)) {
      void sendImageBlob(file, fileNameOrFallback(file));
    }
  });
  composer.addEventListener("submit", (event) => {
    event.preventDefault();
    const value = input.value;
    input.value = "";
    syncInputHeight();
    emojiPanel.classList.remove("open");
    void sendTextMessage(value);
  });
  composerPill.append(emojiWrap, input, attach, fileInput);
  composer.append(composerPill, send);
  main.append(topbar, modeBanner, messages, composer);
  layout.append(sidebar, main);
  setApp(layout);
  syncInputHeight();
  messages.scrollTop = messages.scrollHeight;
}

function showInviteDialog(
  link: string,
  passphrase: string,
  mode: "single-link" | "two-channel"
): void {
  const backdrop = el("div", { className: "modal-backdrop" });
  const dialog = el("section", { className: "dialog" });
  const linkInput = el("textarea", { value: link });
  const pass = el("input", { type: "text", value: passphrase });
  const notice = el("div", { className: "copy-notice" });
  const showCopyNotice = (message: string, isError = false) => {
    notice.textContent = message;
    notice.className = isError ? "copy-notice error" : "copy-notice ok";
  };
  const close = el("button", { className: "primary", text: "关闭" });
  const copyLink = el("button", { className: "secondary", text: "复制链接" });
  copyLink.addEventListener("click", () => {
    void navigator.clipboard
      ?.writeText(link)
      .then(() => showCopyNotice("链接已复制"))
      .catch(() => showCopyNotice("复制失败，请手动复制", true));
  });
  close.addEventListener("click", () => backdrop.remove());
  dialog.append(
    el("h2", { text: "邀请已生成" }),
    el("p", {
      className: "subtle",
      text:
        mode === "two-channel" ? "请用两个独立渠道分别发送链接和口令。" : "单链接包含全部进入秘密。"
    }),
    el("label", { className: "field" }, ["链接", linkInput]),
    notice
  );
  if (mode === "two-channel") {
    const copyPass = el("button", { className: "secondary", text: "复制口令" });
    copyPass.addEventListener("click", () => {
      void navigator.clipboard
        ?.writeText(passphrase)
        .then(() => showCopyNotice("口令已复制"))
        .catch(() => showCopyNotice("复制失败，请手动复制", true));
    });
    dialog.append(
      el("label", { className: "field" }, ["口令", pass]),
      el("div", { className: "actions" }, [copyLink, copyPass, close])
    );
  } else {
    dialog.append(
      el("div", { className: "warning", text: "链接被转发即获得进入能力。" }),
      el("div", { className: "actions" }, [copyLink, close])
    );
  }
  backdrop.append(dialog);
  document.body.append(backdrop);
}

function showImageViewer(src: string, alt: string): void {
  const backdrop = el("div", { className: "image-viewer-backdrop" });
  const viewer = el("div", { className: "image-viewer" });
  const close = el("button", {
    className: "image-viewer-close",
    text: "×",
    ariaLabel: "关闭图片查看"
  });
  const image = el("img", { className: "image-viewer-img", title: alt });
  image.src = src;
  image.alt = alt;
  const closeViewer = () => {
    document.removeEventListener("keydown", onKeydown);
    backdrop.remove();
  };
  const onKeydown = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      closeViewer();
    }
  };
  close.type = "button";
  close.addEventListener("click", closeViewer);
  backdrop.addEventListener("click", closeViewer);
  viewer.addEventListener("click", (event) => {
    event.stopPropagation();
  });
  document.addEventListener("keydown", onKeydown);
  viewer.append(close, image);
  backdrop.append(viewer);
  document.body.append(backdrop);
  close.focus();
}

function showSecurityDetails(): void {
  const state = runtime;
  if (!state) {
    return;
  }
  const backdrop = el("div", { className: "modal-backdrop" });
  const dialog = el("section", { className: "dialog" });
  const close = el("button", { className: "primary", text: "关闭" });
  close.addEventListener("click", () => backdrop.remove());
  dialog.append(
    el("h2", { text: "安全详情" }),
    el("p", { className: "subtle", text: `协议 V${PROTOCOL_VERSION} · Build ${BUILD_HASH}` }),
    el("div", { className: "safety-line", text: `房间安全码：${state.safetyCode}` }),
    el("div", {
      className: "warning",
      text: "Web E2EE 的前提是信任当前加载的前端代码；服务端仍可观察 IP、连接时间、消息大小和房间活跃度。"
    })
  );
  if (state.mode === "single-link") {
    dialog.append(
      el("div", {
        className: "warning",
        text: "当前房间使用单链接模式，邀请链接包含全部进入秘密。"
      })
    );
  }
  for (const peer of state.peers.values()) {
    dialog.append(
      el("div", { className: "security-peer" }, [
        el("div", { className: "member-name", text: peer.displayName }),
        el("div", { className: "safety-line", text: peer.fingerprint })
      ])
    );
  }
  dialog.append(el("div", { className: "actions" }, [close]));
  backdrop.append(dialog);
  document.body.append(backdrop);
}

renderLogin();

window.addEventListener("pagehide", destroyRuntime);
