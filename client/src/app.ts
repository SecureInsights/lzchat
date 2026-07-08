import "./style.css";
import emojiDataUrl from "emoji-picker-element-data/zh/emojibase/data.json?url";
import { toCanvas } from "qrcode";
import { APP_NAME, wsUrlForRoom } from "./config";
import { aesGcmDecrypt, aesGcmEncrypt } from "./crypto/aead";
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
import { asBufferSource, concatBytes, fromUtf8, utf8, zeroize } from "./crypto/bytes";
import { hkdf } from "./crypto/kdf";
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
import { stableJson } from "./crypto/stable-json";
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
  mediaSendRatchet: SendRatchet;
  mediaRecvRatchet: ReceiveRatchet;
  fingerprint: string;
  profileSent: boolean;
  messageWindow: number[];
  mediaMessageWindow: number[];
  mediaByteWindow: Array<{ seenAt: number; bytes: number }>;
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

type CallMediaKind = "audio" | "video";
type CallStatus = "incoming" | "outgoing" | "connecting" | "active";
type CallDirection = "incoming" | "outgoing";
type CallSignalPayload = Extract<
  PlainPayload,
  { type: "call-offer" | "call-answer" | "call-end" }
>;
type CallEndPayload = Extract<PlainPayload, { type: "call-end" }>;
type CallMediaPayload = Extract<PlainPayload, { type: "call-media" }>;
type CallControlPayload = CallEndPayload;
type EncodedChunkType = "key" | "delta";

type EncodedChunkLike = {
  readonly byteLength: number;
  readonly type: EncodedChunkType;
  readonly timestamp: number;
  readonly duration?: number | null;
  copyTo(destination: Uint8Array): void;
};

type VideoFrameLike = CanvasImageSource & {
  readonly displayWidth?: number;
  readonly displayHeight?: number;
  readonly codedWidth?: number;
  readonly codedHeight?: number;
  close(): void;
};

type AudioDataLike = {
  readonly numberOfChannels: number;
  readonly numberOfFrames: number;
  readonly sampleRate: number;
  copyTo(destination: Float32Array, options: { planeIndex: number; format?: string }): void;
  close(): void;
};

type VideoEncoderConfigLike = {
  codec: string;
  width: number;
  height: number;
  bitrate: number;
  framerate: number;
  latencyMode: "realtime";
  hardwareAcceleration: "no-preference" | "prefer-hardware" | "prefer-software";
};

type AudioEncoderConfigLike = {
  codec: string;
  sampleRate: number;
  numberOfChannels: number;
  bitrate: number;
};

type VideoDecoderConfigLike = {
  codec: string;
  codedWidth: number;
  codedHeight: number;
};

type AudioDecoderConfigLike = {
  codec: string;
  sampleRate: number;
  numberOfChannels: number;
};

type VideoEncoderLike = {
  readonly encodeQueueSize: number;
  configure(config: VideoEncoderConfigLike): void;
  encode(frame: VideoFrameLike, options?: { keyFrame?: boolean }): void;
  close(): void;
};

type AudioEncoderLike = {
  readonly encodeQueueSize: number;
  configure(config: AudioEncoderConfigLike): void;
  encode(data: AudioDataLike): void;
  close(): void;
};

type VideoDecoderLike = {
  readonly decodeQueueSize: number;
  configure(config: VideoDecoderConfigLike): void;
  decode(chunk: EncodedChunkLike): void;
  close(): void;
};

type AudioDecoderLike = {
  readonly decodeQueueSize: number;
  configure(config: AudioDecoderConfigLike): void;
  decode(chunk: EncodedChunkLike): void;
  close(): void;
};

type VideoEncoderConstructorLike = {
  new (init: { output: (chunk: EncodedChunkLike) => void; error: (error: Error) => void }): VideoEncoderLike;
  isConfigSupported?: (config: VideoEncoderConfigLike) => Promise<{ supported: boolean; config?: VideoEncoderConfigLike }>;
};

type AudioEncoderConstructorLike = {
  new (init: { output: (chunk: EncodedChunkLike) => void; error: (error: Error) => void }): AudioEncoderLike;
  isConfigSupported?: (config: AudioEncoderConfigLike) => Promise<{ supported: boolean; config?: AudioEncoderConfigLike }>;
};

type VideoDecoderConstructorLike = {
  new (init: { output: (frame: VideoFrameLike) => void; error: (error: Error) => void }): VideoDecoderLike;
};

type AudioDecoderConstructorLike = {
  new (init: { output: (data: AudioDataLike) => void; error: (error: Error) => void }): AudioDecoderLike;
};

type VideoFrameConstructorLike = {
  new (source: CanvasImageSource, init: { timestamp: number }): VideoFrameLike;
};

type EncodedVideoChunkConstructorLike = {
  new (init: { type: EncodedChunkType; timestamp: number; duration?: number; data: Uint8Array }): EncodedChunkLike;
};

type EncodedAudioChunkConstructorLike = EncodedVideoChunkConstructorLike;

type MediaStreamTrackProcessorConstructorLike = {
  new (init: { track: MediaStreamTrack }): { readable: ReadableStream<AudioDataLike> };
};

type CaptureVideoElement = HTMLVideoElement & {
  requestVideoFrameCallback?: (callback: (now: number, metadata: { mediaTime?: number }) => void) => number;
  cancelVideoFrameCallback?: (handle: number) => void;
};

type WebCodecsRuntime = {
  VideoEncoder?: VideoEncoderConstructorLike;
  AudioEncoder?: AudioEncoderConstructorLike;
  VideoDecoder?: VideoDecoderConstructorLike;
  AudioDecoder?: AudioDecoderConstructorLike;
  VideoFrame?: VideoFrameConstructorLike;
  EncodedVideoChunk?: EncodedVideoChunkConstructorLike;
  EncodedAudioChunk?: EncodedAudioChunkConstructorLike;
  MediaStreamTrackProcessor?: MediaStreamTrackProcessorConstructorLike;
};

type EncodedCallPublisher = {
  closed: boolean;
  captureVideo: CaptureVideoElement | null;
  videoEncoder: VideoEncoderLike | null;
  audioEncoder: AudioEncoderLike | null;
  audioReader: ReadableStreamDefaultReader<AudioDataLike> | null;
  videoCallbackId: number;
  videoIntervalId: number;
  videoConfig: VideoEncoderConfigLike | null;
  audioConfig: AudioEncoderConfigLike | null;
  videoSeq: number;
  audioSeq: number;
  lastKeyFrameAt: number;
  lastVideoEncodeAt: number;
};

type EncodedCallReceiver = {
  videoDecoder: VideoDecoderLike | null;
  audioDecoder: AudioDecoderLike | null;
  audioContext: AudioContext | null;
  videoConfigKey: string;
  audioConfigKey: string;
  gotVideoKeyFrame: boolean;
  nextAudioTime: number;
  seenVideoSeq: Set<number>;
  seenAudioSeq: Set<number>;
};

type CallRuntime = {
  callId: string;
  peerId: string;
  peerName: string;
  media: CallMediaKind;
  direction: CallDirection;
  status: CallStatus;
  localStream: MediaStream | null;
  publisher: EncodedCallPublisher | null;
  receiver: EncodedCallReceiver;
  remoteCanvas: HTMLCanvasElement | null;
  mediaSendFailures: number;
  mediaFailureNotified: boolean;
  incomingTimerId: number | null;
  ringtoneTimerId: number | null;
  muted: boolean;
  cameraOff: boolean;
  createdAt: number;
};

type CallMediaGrant = {
  stream: MediaStream;
  warning?: string;
};

type MediaPermissionState = PermissionState | "unsupported";

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
  membersEpoch: number;
  privatePeerId: string | null;
  roomUnread: number;
  privateUnread: Map<string, number>;
  inviteLink: string | null;
  invitePassphrase: string;
  inviteMode: "single-link" | "two-channel";
  incomingFiles: Map<string, IncomingFile>;
  call: CallRuntime | null;
  endedCalls: Map<string, number>;
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
const MAX_ROOM_NAME_CHARS = 60;
const DEFAULT_ROOM_NAME = "临时房间";
const MEDIA_RATCHET_WINDOW = 1024;
const MEDIA_MAX_SKIPPED_KEYS = 1024;
const PEER_MAX_CALL_MEDIA_BYTES_PER_WINDOW = 8 * 1024 * 1024;
const CALL_MAX_VIDEO_CHUNK_BYTES = 128 * 1024;
const CALL_MAX_AUDIO_CHUNK_BYTES = 16 * 1024;
const CALL_MAX_MEDIA_SEND_FAILURES = 8;
const CALL_MAX_AUDIO_QUEUE_DELAY_SEC = 0.8;
const CALL_INCOMING_TIMEOUT_MS = 60_000;
const CALL_RINGTONE_INTERVAL_MS = 1_700;
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
const MIME_TYPE_RE = /^[a-z][a-z0-9]*\/[a-z][a-z0-9]*(?:[.+-][a-z0-9]+)*$/u;
const DANGEROUS_DOWNLOAD_MIME_RE =
  /^(?:text\/html|text\/javascript|application\/(?:javascript|x-javascript|ecmascript|x-msdownload|x-sh|x-bat|x-csh)|image\/svg\+xml)$/u;
const PEER_MAX_CALL_MEDIA_MESSAGES_PER_WINDOW = 2_000;
const CALL_MEDIA_BUFFER_HIGH_WATER_BYTES = 256 * 1024;
const CALL_VIDEO_ENCODER_QUEUE_LIMIT = 2;
const CALL_VIDEO_WIDTH = 640;
const CALL_VIDEO_HEIGHT = 360;
const CALL_VIDEO_FPS = 30;
const CALL_VIDEO_BITRATE = 900_000;
const CALL_VIDEO_BITRATES = [CALL_VIDEO_BITRATE, 700_000, 500_000];
const CALL_VIDEO_HARDWARE_ACCELERATION: VideoEncoderConfigLike["hardwareAcceleration"][] = [
  "no-preference",
  "prefer-hardware",
  "prefer-software"
];
const CALL_KEYFRAME_INTERVAL_MS = 2_000;
const CALL_AUDIO_BITRATE = 48_000;
const CALL_VIDEO_CODECS = [
  "vp8",
  "vp09.00.10.08",
  "vp09.00.10.08.01.01.01.01.00",
  "av01.0.04M.08",
  "av01.0.05M.08",
  "avc1.42001E",
  "avc1.42C01E",
  "avc1.42C01F",
  "avc1.42E01E",
  "avc1.4D401E",
  "avc1.64001E"
];
const INVITE_QR_SIZE = 176;
const ENDED_CALL_CACHE_MS = 5 * 60 * 1000;
const MAX_ENDED_CALL_CACHE = 64;
const CALL_END_RETRY_DELAYS_MS = [0, 250, 1_000];
const CALL_STATUS_TEXT: Record<CallStatus, string> = {
  incoming: "来电",
  outgoing: "呼叫中",
  connecting: "连接中",
  active: "通话中"
};
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

function playCallRingtone(): boolean {
  const context = notificationAudioContext;
  if (!context || context.state !== "running") {
    return false;
  }
  const now = context.currentTime;
  const gain = context.createGain();
  gain.gain.setValueAtTime(0.0001, now);
  gain.gain.exponentialRampToValueAtTime(0.075, now + 0.02);
  gain.gain.setValueAtTime(0.075, now + 0.5);
  gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.62);
  gain.connect(context.destination);

  for (const [offset, frequency] of [
    [0, 660],
    [0.24, 520]
  ] as const) {
    const oscillator = context.createOscillator();
    oscillator.type = "sine";
    oscillator.frequency.setValueAtTime(frequency, now + offset);
    oscillator.connect(gain);
    oscillator.addEventListener(
      "ended",
      () => {
        oscillator.disconnect();
      },
      { once: true }
    );
    oscillator.start(now + offset);
    oscillator.stop(now + offset + 0.28);
  }

  window.setTimeout(() => {
    try {
      gain.disconnect();
    } catch {
      // The audio context may already be closed while leaving the room.
    }
  }, 760);
  return true;
}

function installNotificationSoundUnlock(): void {
  const tryUnlock = () => {
    void unlockNotificationSound()
      .then((ready) => {
        if (!ready) {
          return;
        }
        if (runtime) {
          runtime.soundEnabled = true;
        }
        document.removeEventListener("pointerdown", tryUnlock);
        document.removeEventListener("keydown", tryUnlock);
      })
      .catch(() => undefined);
  };
  document.addEventListener("pointerdown", tryUnlock, { passive: true });
  document.addEventListener("keydown", tryUnlock);
}

function closeNotificationAudio(): void {
  const context = notificationAudioContext;
  notificationAudioContext = null;
  if (context && context.state !== "closed") {
    context.close().catch(() => undefined);
  }
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
  const normalized = value.trim().toLowerCase().slice(0, 120);
  if (!MIME_TYPE_RE.test(normalized) || DANGEROUS_DOWNLOAD_MIME_RE.test(normalized)) {
    return "application/octet-stream";
  }
  return normalized;
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
    const invite = params.get("i");
    if (invite) {
      return invite;
    }
  } catch {
    // Not a URL; fall through to token parsing.
  }
  if (trimmed.includes("i=")) {
    const params = new URLSearchParams(trimmed.replace(/^#/u, ""));
    const invite = params.get("i");
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
  peer.mediaSendRatchet.destroy();
  peer.mediaRecvRatchet.destroy();
  zeroize(peer.pair.rootKey);
  zeroize(peer.pair.sendCK);
  zeroize(peer.pair.recvCK);
  zeroize(peer.pair.mediaSendCK);
  zeroize(peer.pair.mediaRecvCK);
}

function destroyRuntime(): void {
  const state = runtime;
  if (!state) {
    return;
  }
  const activeCall = state.call;
  state.call = null;
  cleanupCall(activeCall);
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
  state.privateUnread.clear();
  state.endedCalls.clear();
  closeNotificationAudio();
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

function shouldReceiveCallMediaEnvelope(state: Runtime, peer: PeerRuntime, envelope: RelayEnvelope): boolean {
  const call = state.call;
  return (
    envelope.kind !== "call-media" ||
    Boolean(call && call.status !== "incoming" && call.peerId === peer.clientId)
  );
}

function shouldReceiveCallControlEnvelope(state: Runtime, peer: PeerRuntime, envelope: RelayEnvelope): boolean {
  const call = state.call;
  return envelope.kind !== "call-control" || Boolean(call && call.peerId === peer.clientId);
}

function acceptPeerRate(peer: PeerRuntime, envelope: RelayEnvelope): boolean {
  const now = Date.now();
  if (envelope.kind === "call-media") {
    peer.mediaMessageWindow = peer.mediaMessageWindow.filter((seen) => now - seen < PEER_MESSAGE_WINDOW_MS);
    peer.mediaMessageWindow.push(now);
    peer.mediaByteWindow = peer.mediaByteWindow.filter((item) => now - item.seenAt < PEER_MESSAGE_WINDOW_MS);
    peer.mediaByteWindow.push({ seenAt: now, bytes: envelope.ct.length });
    const mediaBytes = peer.mediaByteWindow.reduce((sum, item) => sum + item.bytes, 0);
    if (mediaBytes > PEER_MAX_CALL_MEDIA_BYTES_PER_WINDOW) {
      return false;
    }
    return peer.mediaMessageWindow.length <= PEER_MAX_CALL_MEDIA_MESSAGES_PER_WINDOW;
  }
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

function deleteIncomingFilesFromPeer(state: Runtime, peerId: string): void {
  for (const [key, file] of [...state.incomingFiles]) {
    if (file.from === peerId) {
      deleteIncomingFile(state, key);
    }
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
  return `${window.location.origin}${window.location.pathname}#i=${inviteToken}`;
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
    el("span", { text: APP_NAME })
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
        const roomName = roomInput.value.trim().slice(0, MAX_ROOM_NAME_CHARS) || DEFAULT_ROOM_NAME;
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
  const soundReady = await unlockNotificationSound().catch(() => false);
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
    membersEpoch: 0,
    privatePeerId: null,
    roomUnread: 0,
    privateUnread: new Map(),
    inviteLink: input.inviteLink ?? null,
    invitePassphrase: input.invitePassphrase ?? "",
    inviteMode: input.mode,
    call: null,
    endedCalls: new Map(),
    notificationsEnabled: notificationPermission() === "granted",
    soundEnabled: soundReady,
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
  state.membersEpoch += 1;
  const membersEpoch = state.membersEpoch;
  state.safetyCode = "计算中";
  state.members = message.members;
  const liveIds = new Set(message.members.map((member) => member.clientId));
  for (const [clientId, peer] of state.peers) {
    if (!liveIds.has(clientId)) {
      destroyPeer(peer);
      state.peers.delete(clientId);
      state.pendingRelays.delete(clientId);
      state.privateUnread.delete(clientId);
      deleteIncomingFilesFromPeer(state, clientId);
      if (state.call?.peerId === clientId) {
        const activeCall = state.call;
        state.call = null;
        cleanupCall(activeCall);
        addSystemMessage(`${peer.displayName} 已离开，通话已结束。`);
      }
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
      deleteIncomingFilesFromPeer(state, member.clientId);
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
    const mediaSendRatchet = new SendRatchet(pair.mediaSendCK);
    const mediaRecvRatchet = new ReceiveRatchet(pair.mediaRecvCK, MEDIA_RATCHET_WINDOW, MEDIA_MAX_SKIPPED_KEYS);
    zeroize(pair.sendCK);
    zeroize(pair.recvCK);
    zeroize(pair.mediaSendCK);
    zeroize(pair.mediaRecvCK);
    state.peers.set(member.clientId, {
      clientId: member.clientId,
      sessionPub: member.sessionPub,
      displayName: existing?.displayName ?? `临时成员 ${member.clientId.slice(0, 4)}`,
      capabilities: member.capabilities,
      pair,
      sendRatchet,
      recvRatchet,
      mediaSendRatchet,
      mediaRecvRatchet,
      fingerprint: "计算中",
      profileSent: false,
      messageWindow: existing?.messageWindow ?? [],
      mediaMessageWindow: existing?.mediaMessageWindow ?? [],
      mediaByteWindow: existing?.mediaByteWindow ?? [],
      decryptFailures: 0,
      lastFailureNoticeAt: 0
    });
    void updatePeerFingerprint(state, member.clientId, member.sessionPub);
  }
  renderChat();
  await sendProfilesToAll();
  await processPendingRelays();
  void updateRoomSafetyCode(state, message.members, membersEpoch);
}

async function updatePeerFingerprint(
  state: Runtime,
  clientId: string,
  sessionPub: string
): Promise<void> {
  const fingerprint = await peerFingerprint(state.room.roomId, sessionPub);
  if (runtime !== state) {
    return;
  }
  const peer = state.peers.get(clientId);
  if (!peer || peer.sessionPub !== sessionPub) {
    return;
  }
  peer.fingerprint = fingerprint;
  renderChat();
}

async function updateRoomSafetyCode(
  state: Runtime,
  members: MembersMessage["members"],
  membersEpoch: number
): Promise<void> {
  const digest = await rosterDigest(members);
  const safetyCode = await roomSafetyCode(state.room.rosterKey, digest);
  if (runtime !== state || state.membersEpoch !== membersEpoch) {
    return;
  }
  state.safetyCode = safetyCode;
  renderChat();
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
      roomName: state.roomName,
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
  if (!shouldReceiveCallMediaEnvelope(state, peer, envelope)) {
    return;
  }
  if (!shouldReceiveCallControlEnvelope(state, peer, envelope)) {
    return;
  }
  if (!acceptPeerRate(peer, envelope)) {
    return;
  }
  if (envelope.kind === "call-control") {
    const control = await openCallControlEnvelope(envelope, peer);
    if (control) {
      await handleCallSignal(state, peer, control);
    }
    return;
  }
  const payload = await openPayload(
    envelope,
    peer.pair.transcriptHash,
    envelope.kind === "call-media" ? peer.mediaRecvRatchet : peer.recvRatchet
  );
  if (!payload) {
    peer.decryptFailures += 1;
    const now = Date.now();
    if (envelope.kind !== "call-media" && now - peer.lastFailureNoticeAt > FAILURE_NOTICE_INTERVAL_MS) {
      addSystemMessage(`${peer.displayName} 有密文未通过验证，已丢弃。`);
      peer.lastFailureNoticeAt = now;
    }
    return;
  }
  if (envelope.from !== peer.clientId || peer.pair.peerClientId !== envelope.from) {
    return;
  }
  if (payload.type === "profile") {
    peer.displayName = payload.displayName || peer.displayName;
    if (payload.roomName && state.roomName === DEFAULT_ROOM_NAME) {
      state.roomName = payload.roomName;
    }
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
  if (
    payload.type === "call-offer" ||
    payload.type === "call-answer" ||
    payload.type === "call-end"
  ) {
    await handleCallSignal(state, peer, payload);
    return;
  }
  if (payload.type === "call-media") {
    handleCallMedia(state, peer, payload);
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
    tag: `${state.room.roomId}:${message.scope}`
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

async function sendCallSignal(state: Runtime, peer: PeerRuntime, payload: CallSignalPayload): Promise<void> {
  const envelope = await sealPayload({
    roomId: state.room.roomId,
    from: state.clientId,
    to: peer.clientId,
    kind: "call-signal",
    transcriptHash: peer.pair.transcriptHash,
    ratchet: peer.sendRatchet,
    payload
  });
  state.ws.send(envelope);
}

async function sendCallControlSignal(state: Runtime, peer: PeerRuntime, payload: CallControlPayload): Promise<void> {
  const seq = nextControlSeq();
  const aad = utf8(
    stableJson({
      v: 3,
      t: "relay",
      roomId: state.room.roomId,
      from: state.clientId,
      to: peer.clientId,
      kind: "call-control",
      seq,
      transcriptHash: peer.pair.transcriptHash
    })
  );
  const key = await callControlKey(peer);
  const nonce = randomBytes(12);
  try {
    const ct = await aesGcmEncrypt(key, nonce, aad, utf8(stableJson(payload)));
    state.ws.send({
      v: 3,
      t: "relay",
      roomId: state.room.roomId,
      from: state.clientId,
      to: peer.clientId,
      kind: "call-control",
      seq,
      nonce: base64urlEncode(nonce),
      ct: base64urlEncode(ct)
    } satisfies RelayEnvelope);
  } finally {
    zeroize(key);
    zeroize(nonce);
  }
}

async function openCallControlEnvelope(envelope: RelayEnvelope, peer: PeerRuntime): Promise<CallControlPayload | null> {
  const aad = utf8(
    stableJson({
      v: 3,
      t: "relay",
      roomId: envelope.roomId,
      from: envelope.from,
      to: envelope.to,
      kind: envelope.kind,
      seq: envelope.seq,
      transcriptHash: peer.pair.transcriptHash
    })
  );
  const key = await callControlKey(peer);
  let plaintext: Uint8Array | null = null;
  try {
    plaintext = await aesGcmDecrypt(key, base64urlDecode(envelope.nonce), aad, base64urlDecode(envelope.ct));
    const payload = JSON.parse(fromUtf8(plaintext));
    return isCallControlPayload(payload) ? payload : null;
  } catch {
    return null;
  } finally {
    if (plaintext) {
      zeroize(plaintext);
    }
    zeroize(key);
  }
}

function sendCallEndSignal(
  state: Runtime,
  peer: PeerRuntime,
  callId: string,
  reason: string
): void {
  rememberEndedCall(state, peer.clientId, callId);
  const payload = (): CallEndPayload => ({
    type: "call-end",
    callId,
    reason,
    createdAt: Date.now()
  });
  for (const delay of CALL_END_RETRY_DELAYS_MS) {
    window.setTimeout(() => {
      if (runtime !== state || !state.peers.has(peer.clientId)) {
        return;
      }
      void sendCallControlSignal(state, peer, payload()).catch(() => undefined);
      void sendCallSignal(state, peer, payload()).catch(() => undefined);
    }, delay);
  }
}

async function sendCallMedia(state: Runtime, peer: PeerRuntime, payload: CallMediaPayload): Promise<boolean> {
  if (state.ws.bufferedAmount() > CALL_MEDIA_BUFFER_HIGH_WATER_BYTES) {
    return false;
  }
  const envelope = await sealPayload({
    roomId: state.room.roomId,
    from: state.clientId,
    to: peer.clientId,
    kind: "call-media",
    transcriptHash: peer.pair.transcriptHash,
    ratchet: peer.mediaSendRatchet,
    payload
  });
  return state.ws.send(envelope);
}

function webCodecsRuntime(): WebCodecsRuntime {
  return globalThis as unknown as WebCodecsRuntime;
}

function createEncodedReceiver(): EncodedCallReceiver {
  return {
    videoDecoder: null,
    audioDecoder: null,
    audioContext: null,
    videoConfigKey: "",
    audioConfigKey: "",
    gotVideoKeyFrame: false,
    nextAudioTime: 0,
    seenVideoSeq: new Set(),
    seenAudioSeq: new Set()
  };
}

async function callControlKey(peer: PeerRuntime): Promise<Uint8Array> {
  return hkdf(
    peer.pair.rootKey,
    "secure-chat/v3/call-control",
    base64urlDecode(peer.pair.transcriptHash),
    32
  );
}

function nextControlSeq(): number {
  return Date.now() * 1_000 + Math.floor(Math.random() * 1_000);
}

function isCallControlPayload(value: unknown): value is CallControlPayload {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const payload = value as Record<string, unknown>;
  return (
    payload.type === "call-end" &&
    typeof payload.callId === "string" &&
    /^[A-Za-z0-9_-]{1,128}$/u.test(payload.callId) &&
    (payload.reason === undefined || (typeof payload.reason === "string" && payload.reason.length <= 120)) &&
    typeof payload.createdAt === "number" &&
    Number.isSafeInteger(payload.createdAt) &&
    payload.createdAt > 0
  );
}

function cleanupCall(call: CallRuntime | null): void {
  if (!call) {
    return;
  }
  stopCallRingtone(call);
  if (call.incomingTimerId !== null) {
    window.clearTimeout(call.incomingTimerId);
    call.incomingTimerId = null;
  }
  call.localStream?.getTracks().forEach((track) => track.stop());
  call.localStream = null;
  cleanupEncodedPublisher(call.publisher);
  call.publisher = null;
  cleanupEncodedReceiver(call.receiver);
  call.remoteCanvas = null;
}

function stopCallRingtone(call: CallRuntime): void {
  if (call.ringtoneTimerId !== null) {
    window.clearInterval(call.ringtoneTimerId);
    call.ringtoneTimerId = null;
  }
}

function callPeer(state: Runtime, call: CallRuntime): PeerRuntime | null {
  return state.peers.get(call.peerId) ?? null;
}

function endedCallKey(peerId: string, callId: string): string {
  return `${peerId}:${callId}`;
}

function pruneEndedCalls(state: Runtime): void {
  const now = Date.now();
  for (const [key, seenAt] of state.endedCalls) {
    if (now - seenAt > ENDED_CALL_CACHE_MS) {
      state.endedCalls.delete(key);
    }
  }
  while (state.endedCalls.size > MAX_ENDED_CALL_CACHE) {
    const firstKey = state.endedCalls.keys().next().value as string | undefined;
    if (!firstKey) {
      return;
    }
    state.endedCalls.delete(firstKey);
  }
}

function rememberEndedCall(state: Runtime, peerId: string, callId: string): void {
  pruneEndedCalls(state);
  state.endedCalls.set(endedCallKey(peerId, callId), Date.now());
}

function hasEndedCall(state: Runtime, peerId: string, callId: string): boolean {
  pruneEndedCalls(state);
  return state.endedCalls.has(endedCallKey(peerId, callId));
}

function mediaLabel(media: CallMediaKind): string {
  return media === "video" ? "视频" : "语音";
}

function callVideoConstraints(): MediaTrackConstraints {
  return {
    width: { ideal: CALL_VIDEO_WIDTH },
    height: { ideal: CALL_VIDEO_HEIGHT },
    frameRate: { ideal: CALL_VIDEO_FPS, max: CALL_VIDEO_FPS }
  };
}

async function queryMediaPermission(name: "microphone" | "camera"): Promise<MediaPermissionState> {
  const permissions = navigator.permissions;
  if (!permissions?.query) {
    return "unsupported";
  }
  try {
    const result = await permissions.query({ name: name as PermissionName });
    return result.state;
  } catch {
    return "unsupported";
  }
}

async function describeMediaPermissions(media: CallMediaKind): Promise<string | null> {
  const microphone = await queryMediaPermission("microphone");
  const camera = media === "video" ? await queryMediaPermission("camera") : "unsupported";
  if (microphone === "denied" && media === "audio") {
    return "麦克风权限已被浏览器拦截，请点击地址栏左侧图标，在站点设置里允许麦克风。";
  }
  if (media === "video" && microphone === "denied" && camera === "denied") {
    return "摄像头和麦克风权限已被浏览器拦截，请点击地址栏左侧图标，在站点设置里允许后刷新。";
  }
  if (media === "video" && camera === "denied") {
    return "摄像头权限已被浏览器拦截，请点击地址栏左侧图标，在站点设置里允许摄像头。";
  }
  if (media === "video" && microphone === "denied") {
    return "麦克风权限已被浏览器拦截，将尝试只发送视频。";
  }
  if (microphone === "prompt" || camera === "prompt") {
    return "浏览器将请求通话权限，请在弹窗中选择允许。";
  }
  return null;
}

async function getCallMedia(media: CallMediaKind): Promise<CallMediaGrant> {
  if (!navigator.mediaDevices?.getUserMedia) {
    throw new Error("media devices unavailable");
  }
  if (media === "audio") {
    return {
      stream: await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: false
      })
    };
  }
  try {
    return {
      stream: await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: callVideoConstraints()
      })
    };
  } catch (error) {
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: callVideoConstraints()
    });
    return {
      stream,
      warning: `麦克风不可用，已只发送视频。原始原因：${mediaErrorText(error, "video")}`
    };
  }
}

function mediaErrorText(error: unknown, media: CallMediaKind): string {
  if (typeof error === "object" && error !== null && "name" in error) {
    const name = String((error as { name?: unknown }).name ?? "");
    const message = "message" in error ? String((error as { message?: unknown }).message ?? "") : "";
    if (name === "NotAllowedError") {
      return media === "audio" ? "浏览器拒绝了麦克风权限" : "浏览器拒绝了摄像头或麦克风权限";
    }
    if (name === "NotFoundError" || name === "DevicesNotFoundError") {
      return media === "audio" ? "未找到可用的麦克风" : "未找到可用的摄像头或麦克风";
    }
    if (name === "NotReadableError" || name === "TrackStartError") {
      return "设备可能被其他应用占用";
    }
    if (name === "OverconstrainedError") {
      return "设备不支持当前采集参数";
    }
    if (name === "SecurityError") {
      return "当前页面不允许访问媒体设备";
    }
    if (name === "AbortError") {
      return "设备启动被中断";
    }
    return message || name;
  }
  return error instanceof Error ? error.message : "未知错误";
}

function rawMediaErrorText(error: unknown): string {
  if (typeof error === "object" && error !== null && "name" in error) {
    const name = String((error as { name?: unknown }).name ?? "");
    const message = "message" in error ? String((error as { message?: unknown }).message ?? "") : "";
    return [name, message].filter(Boolean).join(": ");
  }
  return error instanceof Error ? error.message : String(error);
}

function drawVideoContain(
  context: CanvasRenderingContext2D,
  video: HTMLVideoElement,
  width: number,
  height: number
): void {
  const sourceWidth = video.videoWidth || width;
  const sourceHeight = video.videoHeight || height;
  const scale = Math.min(width / sourceWidth, height / sourceHeight);
  const targetWidth = Math.max(1, Math.round(sourceWidth * scale));
  const targetHeight = Math.max(1, Math.round(sourceHeight * scale));
  const targetX = Math.floor((width - targetWidth) / 2);
  const targetY = Math.floor((height - targetHeight) / 2);
  context.fillStyle = "#111827";
  context.fillRect(0, 0, width, height);
  context.drawImage(video, 0, 0, sourceWidth, sourceHeight, targetX, targetY, targetWidth, targetHeight);
}

function isNotAllowedMediaError(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "name" in error &&
    String((error as { name?: unknown }).name ?? "") === "NotAllowedError"
  );
}

function permissionStateText(state: MediaPermissionState): string {
  if (state === "granted") {
    return "允许";
  }
  if (state === "denied") {
    return "拒绝";
  }
  if (state === "prompt") {
    return "询问";
  }
  return "未知";
}

async function callFailureText(action: "发起" | "接听", media: CallMediaKind, error: unknown): Promise<string> {
  const base = `无法${action}${mediaLabel(media)}通话：${mediaErrorText(error, media)}。`;
  const detail = rawMediaErrorText(error);
  const microphone = await queryMediaPermission("microphone");
  const camera = media === "video" ? await queryMediaPermission("camera") : "unsupported";
  const permissionDetail =
    media === "video"
      ? `当前权限：麦克风${permissionStateText(microphone)}，摄像头${permissionStateText(camera)}。`
      : `当前权限：麦克风${permissionStateText(microphone)}。`;
  const originHint =
    window.location.hostname === "127.0.0.1"
      ? "如果权限已允许但仍失败，请刷新后改用 http://localhost:8088 再试。"
      : "";
  const secureHint = window.isSecureContext ? "" : "当前页面不是安全上下文，请改用 localhost 或 HTTPS。";
  const systemHint =
    isNotAllowedMediaError(error) && (microphone === "granted" || camera === "granted")
      ? "站点权限已显示允许但仍被拒绝时，通常是系统隐私权限、浏览器策略或设备沙盒拦截。"
      : "";
  const showDebugDetail = window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost";
  return [base, permissionDetail, secureHint, systemHint, originHint, showDebugDetail && detail ? `浏览器返回：${detail}` : ""]
    .filter(Boolean)
    .join(" ");
}

function startIncomingRingtone(state: Runtime, call: CallRuntime): void {
  if (call.ringtoneTimerId !== null) {
    return;
  }
  const start = () => {
    if (runtime !== state || state.call !== call || call.status !== "incoming" || call.ringtoneTimerId !== null) {
      return;
    }
    if (!playCallRingtone()) {
      return;
    }
    call.ringtoneTimerId = window.setInterval(() => {
      if (runtime !== state || state.call !== call || call.status !== "incoming") {
        stopCallRingtone(call);
        return;
      }
      playCallRingtone();
    }, CALL_RINGTONE_INTERVAL_MS);
  };
  if (notificationAudioContext?.state === "running") {
    state.soundEnabled = true;
    start();
    return;
  }
  if (!state.soundEnabled) {
    return;
  }
  void unlockNotificationSound()
    .then((ready) => {
      state.soundEnabled = ready;
      if (ready) {
        start();
      }
    })
    .catch(() => undefined);
}

function notifyIncomingCall(state: Runtime, call: CallRuntime, peer: PeerRuntime, media: CallMediaKind): void {
  startIncomingRingtone(state, call);
  if (!state.notificationsEnabled || notificationPermission() !== "granted" || isWindowActive()) {
    return;
  }
  const notification = new Notification(`${peer.displayName} 发起${mediaLabel(media)}通话`, {
    body: "打开页面接听或拒绝",
    tag: `${state.room.roomId}:call:${peer.clientId}`
  });
  notification.addEventListener("click", () => {
    window.focus();
    notification.close();
  });
}

function scheduleIncomingCallTimeout(state: Runtime, call: CallRuntime, peer: PeerRuntime): void {
  call.incomingTimerId = window.setTimeout(() => {
    if (runtime !== state || state.call !== call || call.status !== "incoming") {
      return;
    }
    state.call = null;
    cleanupCall(call);
    rememberEndedCall(state, peer.clientId, call.callId);
    addSystemMessage("来电已超时。");
    renderChat();
    sendCallEndSignal(state, peer, call.callId, "timeout");
  }, CALL_INCOMING_TIMEOUT_MS);
}

function canUseEncodedCall(media: CallMediaKind): boolean {
  const codecs = webCodecsRuntime();
  const hasVideo =
    Boolean(codecs.VideoEncoder) &&
    Boolean(codecs.VideoDecoder) &&
    Boolean(codecs.VideoFrame) &&
    Boolean(codecs.EncodedVideoChunk);
  const hasAudio =
    Boolean(codecs.AudioEncoder) &&
    Boolean(codecs.AudioDecoder) &&
    Boolean(codecs.EncodedAudioChunk) &&
    Boolean(codecs.MediaStreamTrackProcessor);
  if (media === "audio") {
    return hasAudio;
  }
  return hasVideo;
}

async function startPrivateCall(peer: PeerRuntime, media: CallMediaKind): Promise<void> {
  const state = runtime;
  if (!state) {
    return;
  }
  if (state.call) {
    addSystemMessage("当前已有通话，请先挂断。");
    return;
  }
  const call: CallRuntime = {
    callId: base64urlEncode(randomBytes(12)),
    peerId: peer.clientId,
    peerName: peer.displayName,
    media,
    direction: "outgoing",
    status: "connecting",
    localStream: null,
    publisher: null,
    receiver: createEncodedReceiver(),
    remoteCanvas: null,
    mediaSendFailures: 0,
    mediaFailureNotified: false,
    incomingTimerId: null,
    ringtoneTimerId: null,
    muted: false,
    cameraOff: false,
    createdAt: Date.now()
  };
  state.call = call;
  state.privatePeerId = peer.clientId;
  renderChat();
  try {
    const permissionNotice = await describeMediaPermissions(media);
    if (permissionNotice) {
      addSystemMessage(permissionNotice);
    }
    const mediaGrant = await getCallMedia(media);
    call.localStream = mediaGrant.stream;
    if (runtime !== state || state.call !== call) {
      cleanupCall(call);
      return;
    }
    if (mediaGrant.warning) {
      addSystemMessage(mediaGrant.warning);
    }
    if (!canUseEncodedCall(media)) {
      throw new Error("当前浏览器不支持 WebCodecs 加密通话");
    }
    if (media === "video") {
      await selectVideoConfig();
    }
    await sendCallSignal(state, peer, {
      type: "call-offer",
      callId: call.callId,
      media,
      mode: "encoded-media",
      targetIds: [peer.clientId],
      createdAt: Date.now()
    });
    call.status = "outgoing";
    renderChat();
  } catch (error) {
    cleanupCall(call);
    if (state.call === call) {
      state.call = null;
      renderChat();
    }
    addSystemMessage(await callFailureText("发起", media, error));
  }
}

async function acceptIncomingCall(): Promise<void> {
  const state = runtime;
  const call = state?.call;
  if (!state || !call || call.direction !== "incoming") {
    return;
  }
  const peer = callPeer(state, call);
  if (!peer) {
    await finishCall("对方已离线", false);
    return;
  }
  call.status = "connecting";
  stopCallRingtone(call);
  if (call.incomingTimerId !== null) {
    window.clearTimeout(call.incomingTimerId);
    call.incomingTimerId = null;
  }
  renderChat();
  try {
    const permissionNotice = await describeMediaPermissions(call.media);
    if (permissionNotice) {
      addSystemMessage(permissionNotice);
    }
    const mediaGrant = await getCallMedia(call.media);
    call.localStream = mediaGrant.stream;
    if (runtime !== state || state.call !== call) {
      cleanupCall(call);
      return;
    }
    if (mediaGrant.warning) {
      addSystemMessage(mediaGrant.warning);
    }
    if (!canUseEncodedCall(call.media)) {
      throw new Error("当前浏览器不支持 WebCodecs 加密通话");
    }
    if (call.media === "video") {
      await selectVideoConfig();
    }
    await sendCallSignal(state, peer, {
      type: "call-answer",
      callId: call.callId,
      mode: "encoded-media",
      createdAt: Date.now()
    });
    call.status = "active";
    await startEncodedPublisher(state, call, peer);
    renderChat();
  } catch (error) {
    await finishCall("无法接听通话", true);
    addSystemMessage(await callFailureText("接听", call.media, error));
  }
}

async function finishCall(reason = "ended", notifyPeer = true): Promise<void> {
  const state = runtime;
  const call = state?.call;
  if (!state || !call) {
    return;
  }
  const peer = callPeer(state, call);
  if (peer && notifyPeer) {
    sendCallEndSignal(state, peer, call.callId, reason);
  } else if (peer) {
    rememberEndedCall(state, peer.clientId, call.callId);
  }
  state.call = null;
  cleanupCall(call);
  renderChat();
}

async function handleCallSignal(
  state: Runtime,
  peer: PeerRuntime,
  payload: CallSignalPayload
): Promise<void> {
  if (payload.type === "call-offer") {
    if (hasEndedCall(state, peer.clientId, payload.callId)) {
      return;
    }
    if (state.call && state.call.callId !== payload.callId) {
      sendCallEndSignal(state, peer, payload.callId, "busy");
      return;
    }
    if (payload.targetIds && payload.targetIds.length > 0 && !payload.targetIds.includes(state.clientId)) {
      return;
    }
    state.call = {
      callId: payload.callId,
      peerId: peer.clientId,
      peerName: peer.displayName,
      media: payload.media,
      direction: "incoming",
      status: "incoming",
      localStream: null,
      publisher: null,
      receiver: createEncodedReceiver(),
      remoteCanvas: null,
      mediaSendFailures: 0,
      mediaFailureNotified: false,
      incomingTimerId: null,
      ringtoneTimerId: null,
      muted: false,
      cameraOff: false,
      createdAt: payload.createdAt
    };
    state.privatePeerId = peer.clientId;
    scheduleIncomingCallTimeout(state, state.call, peer);
    notifyIncomingCall(state, state.call, peer, payload.media);
    addSystemMessage(`${peer.displayName} 发起${mediaLabel(payload.media)}通话。`);
    renderChat();
    return;
  }
  const call = state.call;
  if (payload.type === "call-end") {
    rememberEndedCall(state, peer.clientId, payload.callId);
    if (!call || call.callId !== payload.callId || call.peerId !== peer.clientId) {
      return;
    }
    const message =
      payload.reason === "busy"
        ? `${peer.displayName} 正在通话中。`
        : payload.reason === "rejected"
          ? `${peer.displayName} 已拒绝通话。`
          : payload.reason === "timeout"
            ? "通话未接听，已超时。"
            : "通话已结束。";
    cleanupCall(call);
    state.call = null;
    addSystemMessage(message);
    renderChat();
    return;
  }
  if (!call || call.callId !== payload.callId || call.peerId !== peer.clientId) {
    return;
  }
  if (payload.type === "call-answer") {
    if (call.direction === "outgoing") {
      try {
        call.status = "active";
        await startEncodedPublisher(state, call, peer);
        renderChat();
      } catch {
        cleanupCall(call);
        state.call = null;
        renderChat();
        addSystemMessage("通话媒体启动失败，已结束通话。");
        sendCallEndSignal(state, peer, call.callId, "media-failed");
      }
    }
    return;
  }
}

async function selectVideoConfig(): Promise<VideoEncoderConfigLike> {
  const codecs = webCodecsRuntime();
  const encoder = codecs.VideoEncoder;
  if (!encoder) {
    throw new Error("VideoEncoder unavailable");
  }
  for (const codec of CALL_VIDEO_CODECS) {
    for (const hardwareAcceleration of CALL_VIDEO_HARDWARE_ACCELERATION) {
      for (const bitrate of CALL_VIDEO_BITRATES) {
        const config: VideoEncoderConfigLike = {
          codec,
          width: CALL_VIDEO_WIDTH,
          height: CALL_VIDEO_HEIGHT,
          bitrate,
          framerate: CALL_VIDEO_FPS,
          latencyMode: "realtime",
          hardwareAcceleration
        };
        if (!encoder.isConfigSupported) {
          return config;
        }
        try {
          const support = await encoder.isConfigSupported(config);
          if (support.supported) {
            return { ...config, ...(support.config ?? {}) };
          }
        } catch {
          // Try the next encoder profile.
        }
      }
    }
  }
  throw new Error("No supported video encoder");
}

async function startEncodedPublisher(state: Runtime, call: CallRuntime, peer: PeerRuntime): Promise<void> {
  if (call.publisher || !call.localStream) {
    return;
  }
  const publisher: EncodedCallPublisher = {
    closed: false,
    captureVideo: null,
    videoEncoder: null,
    audioEncoder: null,
    audioReader: null,
    videoCallbackId: 0,
    videoIntervalId: 0,
    videoConfig: null,
    audioConfig: null,
    videoSeq: 0,
    audioSeq: 0,
    lastKeyFrameAt: 0,
    lastVideoEncodeAt: 0
  };
  call.publisher = publisher;
  let startedTrack = false;
  if (call.media === "video") {
    await startEncodedVideo(state, call, peer, publisher);
    startedTrack = true;
  }
  const startedAudio = await startEncodedAudio(state, call, peer, publisher);
  startedTrack = startedTrack || startedAudio;
  if (!startedTrack) {
    cleanupEncodedPublisher(publisher);
    call.publisher = null;
    throw new Error("No supported media encoder");
  }
}

async function startEncodedVideo(
  state: Runtime,
  call: CallRuntime,
  peer: PeerRuntime,
  publisher: EncodedCallPublisher
): Promise<void> {
  const codecs = webCodecsRuntime();
  if (!call.localStream || !codecs.VideoEncoder || !codecs.VideoFrame) {
    throw new Error("VideoEncoder unavailable");
  }
  const video = document.createElement("video") as CaptureVideoElement;
  video.srcObject = call.localStream;
  video.muted = true;
  video.playsInline = true;
  await video.play();
  publisher.captureVideo = video;
  const captureCanvas = document.createElement("canvas");
  captureCanvas.width = CALL_VIDEO_WIDTH;
  captureCanvas.height = CALL_VIDEO_HEIGHT;
  const captureContext = captureCanvas.getContext("2d", { alpha: false });
  if (!captureContext) {
    throw new Error("Canvas capture unavailable");
  }
  publisher.videoConfig = await selectVideoConfig();
  publisher.videoEncoder = new codecs.VideoEncoder({
    output: (chunk) => {
      void sendEncodedVideoChunk(state, call, peer, publisher, chunk);
    },
    error: () => {
      if (runtime === state && state.call === call) {
        addSystemMessage("视频编码器异常，已停止发送视频。");
      }
    }
  });
  publisher.videoEncoder.configure(publisher.videoConfig);
  const encodeFrame = (now: number, metadata: { mediaTime?: number } | null) => {
    if (publisher.closed || runtime !== state || state.call !== call || !publisher.videoEncoder) {
      return;
    }
    const queueSize = publisher.videoEncoder.encodeQueueSize;
    const congested =
      queueSize >= CALL_VIDEO_ENCODER_QUEUE_LIMIT ||
      state.ws.bufferedAmount() > CALL_MEDIA_BUFFER_HIGH_WATER_BYTES;
    const tooSoon =
      publisher.lastVideoEncodeAt > 0 &&
      now - publisher.lastVideoEncodeAt < (1000 / CALL_VIDEO_FPS) * 0.75;
    if (!call.cameraOff && !congested && !tooSoon && video.readyState >= 2) {
      const timestamp = Math.round(
        metadata && Number.isFinite(metadata.mediaTime)
          ? (metadata.mediaTime ?? 0) * 1_000_000
          : performance.now() * 1_000
      );
      try {
        const FrameCtor = codecs.VideoFrame;
        if (!FrameCtor) {
          return;
        }
        drawVideoContain(captureContext, video, CALL_VIDEO_WIDTH, CALL_VIDEO_HEIGHT);
        const frame = new FrameCtor(captureCanvas, { timestamp });
        const keyFrame =
          publisher.lastKeyFrameAt === 0 || now - publisher.lastKeyFrameAt >= CALL_KEYFRAME_INTERVAL_MS;
        publisher.videoEncoder.encode(frame, { keyFrame });
        frame.close();
        publisher.lastVideoEncodeAt = now;
        if (keyFrame) {
          publisher.lastKeyFrameAt = now;
        }
      } catch {
        // Skip a bad frame without surfacing noisy decoder details.
      }
    } else if (congested) {
      publisher.lastKeyFrameAt = 0;
    }
    if (video.requestVideoFrameCallback) {
      publisher.videoCallbackId = video.requestVideoFrameCallback(encodeFrame);
    }
  };
  if (video.requestVideoFrameCallback) {
    publisher.videoCallbackId = video.requestVideoFrameCallback(encodeFrame);
  } else {
    publisher.videoIntervalId = window.setInterval(() => {
      encodeFrame(performance.now(), null);
    }, Math.max(16, Math.round(1000 / CALL_VIDEO_FPS)));
  }
}

async function sendEncodedVideoChunk(
  state: Runtime,
  call: CallRuntime,
  peer: PeerRuntime,
  publisher: EncodedCallPublisher,
  chunk: EncodedChunkLike
): Promise<void> {
  if (publisher.closed || runtime !== state || state.call !== call || !publisher.videoConfig) {
    return;
  }
  const bytes = new Uint8Array(chunk.byteLength);
  chunk.copyTo(bytes);
  try {
    if (bytes.byteLength > CALL_MAX_VIDEO_CHUNK_BYTES) {
      return;
    }
    const sent = await sendCallMedia(state, peer, {
      type: "call-media",
      callId: call.callId,
      media: "video",
      seq: publisher.videoSeq,
      codec: publisher.videoConfig.codec,
      chunkType: chunk.type,
      timestamp: chunk.timestamp,
      duration: Number(chunk.duration ?? 0),
      width: CALL_VIDEO_WIDTH,
      height: CALL_VIDEO_HEIGHT,
      bytes: base64urlEncode(bytes),
      createdAt: Date.now()
    });
    if (!sent) {
      publisher.lastKeyFrameAt = 0;
      return;
    }
    call.mediaSendFailures = 0;
    publisher.videoSeq += 1;
  } catch {
    handleMediaSendFailure(call);
  } finally {
    zeroize(bytes);
  }
}

async function startEncodedAudio(
  state: Runtime,
  call: CallRuntime,
  peer: PeerRuntime,
  publisher: EncodedCallPublisher
): Promise<boolean> {
  const codecs = webCodecsRuntime();
  if (
    !call.localStream ||
    !codecs.AudioEncoder ||
    !codecs.MediaStreamTrackProcessor ||
    !codecs.EncodedAudioChunk
  ) {
    return false;
  }
  const track = call.localStream.getAudioTracks()[0];
  if (!track) {
    return false;
  }
  const settings = track.getSettings();
  const config: AudioEncoderConfigLike = {
    codec: "opus",
    sampleRate: typeof settings.sampleRate === "number" ? settings.sampleRate : 48_000,
    numberOfChannels: typeof settings.channelCount === "number" ? Math.max(1, Math.min(2, settings.channelCount)) : 1,
    bitrate: CALL_AUDIO_BITRATE
  };
  try {
    const support = codecs.AudioEncoder.isConfigSupported
      ? await codecs.AudioEncoder.isConfigSupported(config)
      : { supported: true, config };
    if (!support.supported) {
      return false;
    }
    publisher.audioConfig = support.config ?? config;
    publisher.audioEncoder = new codecs.AudioEncoder({
      output: (chunk) => {
        void sendEncodedAudioChunk(state, call, peer, publisher, chunk);
      },
      error: () => undefined
    });
    publisher.audioEncoder.configure(publisher.audioConfig);
    const processor = new codecs.MediaStreamTrackProcessor({ track });
    publisher.audioReader = processor.readable.getReader();
    void readEncodedAudioFrames(publisher);
    return true;
  } catch {
    publisher.audioEncoder = null;
    publisher.audioReader = null;
    return false;
  }
}

async function readEncodedAudioFrames(publisher: EncodedCallPublisher): Promise<void> {
  while (!publisher.closed && publisher.audioReader && publisher.audioEncoder) {
    const next = await publisher.audioReader.read().catch(() => null);
    if (!next || next.done) {
      break;
    }
    const audioData = next.value;
    if (publisher.audioEncoder.encodeQueueSize < 8) {
      publisher.audioEncoder.encode(audioData);
    }
    audioData.close();
  }
}

async function sendEncodedAudioChunk(
  state: Runtime,
  call: CallRuntime,
  peer: PeerRuntime,
  publisher: EncodedCallPublisher,
  chunk: EncodedChunkLike
): Promise<void> {
  if (publisher.closed || runtime !== state || state.call !== call || !publisher.audioConfig || call.muted) {
    return;
  }
  const bytes = new Uint8Array(chunk.byteLength);
  chunk.copyTo(bytes);
  try {
    if (bytes.byteLength > CALL_MAX_AUDIO_CHUNK_BYTES) {
      return;
    }
    const sent = await sendCallMedia(state, peer, {
      type: "call-media",
      callId: call.callId,
      media: "audio",
      seq: publisher.audioSeq,
      codec: publisher.audioConfig.codec,
      chunkType: chunk.type,
      timestamp: chunk.timestamp,
      duration: Number(chunk.duration ?? 0),
      sampleRate: publisher.audioConfig.sampleRate,
      numberOfChannels: publisher.audioConfig.numberOfChannels,
      bytes: base64urlEncode(bytes),
      createdAt: Date.now()
    });
    if (!sent) {
      return;
    }
    call.mediaSendFailures = 0;
    publisher.audioSeq += 1;
  } catch {
    handleMediaSendFailure(call);
  } finally {
    zeroize(bytes);
  }
}

function handleMediaSendFailure(call: CallRuntime): void {
  call.mediaSendFailures += 1;
  if (call.mediaFailureNotified || call.mediaSendFailures < CALL_MAX_MEDIA_SEND_FAILURES) {
    return;
  }
  call.mediaFailureNotified = true;
  addSystemMessage("媒体发送连续失败，通话已自动结束。");
  void finishCall("media-send-failed", true);
}

function cleanupEncodedPublisher(publisher: EncodedCallPublisher | null): void {
  if (!publisher) {
    return;
  }
  publisher.closed = true;
  if (publisher.captureVideo?.cancelVideoFrameCallback && publisher.videoCallbackId) {
    publisher.captureVideo.cancelVideoFrameCallback(publisher.videoCallbackId);
  }
  if (publisher.videoIntervalId) {
    window.clearInterval(publisher.videoIntervalId);
  }
  publisher.audioReader?.cancel().catch(() => undefined);
  try {
    publisher.videoEncoder?.close();
  } catch {
    // Already closed.
  }
  try {
    publisher.audioEncoder?.close();
  } catch {
    // Already closed.
  }
  if (publisher.captureVideo) {
    publisher.captureVideo.srcObject = null;
  }
  publisher.captureVideo = null;
  publisher.videoEncoder = null;
  publisher.audioEncoder = null;
  publisher.audioReader = null;
}

function cleanupEncodedReceiver(receiver: EncodedCallReceiver): void {
  try {
    receiver.videoDecoder?.close();
  } catch {
    // Already closed.
  }
  try {
    receiver.audioDecoder?.close();
  } catch {
    // Already closed.
  }
  receiver.audioContext?.close().catch(() => undefined);
  receiver.videoDecoder = null;
  receiver.audioDecoder = null;
  receiver.audioContext = null;
  receiver.seenVideoSeq.clear();
  receiver.seenAudioSeq.clear();
}

function trimSeenMediaSeq(seen: Set<number>, seq: number): boolean {
  if (seen.has(seq)) {
    return false;
  }
  seen.add(seq);
  if (seen.size > 256) {
    const minRetained = seq - 256;
    for (const item of [...seen]) {
      if (item < minRetained) {
        seen.delete(item);
      }
    }
  }
  return true;
}

function handleCallMedia(state: Runtime, peer: PeerRuntime, payload: CallMediaPayload): void {
  const call = state.call;
  if (!call || call.callId !== payload.callId || call.peerId !== peer.clientId || call.status === "incoming") {
    return;
  }
  if (payload.media === "video") {
    if (call.media !== "video" || !trimSeenMediaSeq(call.receiver.seenVideoSeq, payload.seq)) {
      return;
    }
    decodeCallVideo(state, call, payload);
    return;
  }
  if (!trimSeenMediaSeq(call.receiver.seenAudioSeq, payload.seq)) {
    return;
  }
  decodeCallAudio(call, payload);
}

function decodeCallVideo(state: Runtime, call: CallRuntime, payload: CallMediaPayload): void {
  const codecs = webCodecsRuntime();
  if (!codecs.VideoDecoder || !codecs.EncodedVideoChunk || !payload.width || !payload.height) {
    return;
  }
  const receiver = call.receiver;
  const configKey = `${payload.codec}:${payload.width}:${payload.height}`;
  try {
    if (!receiver.videoDecoder || receiver.videoConfigKey !== configKey) {
      receiver.videoDecoder?.close();
      receiver.videoDecoder = new codecs.VideoDecoder({
        output: (frame) => {
          try {
            drawDecodedVideoFrame(call, frame);
          } catch {
            frame.close();
          }
        },
        error: () => {
          if (runtime === state && state.call === call) {
            receiver.gotVideoKeyFrame = false;
          }
        }
      });
      receiver.videoDecoder.configure({
        codec: payload.codec,
        codedWidth: payload.width,
        codedHeight: payload.height
      });
      receiver.videoConfigKey = configKey;
      receiver.gotVideoKeyFrame = false;
    }
  } catch {
    receiver.videoDecoder?.close();
    receiver.videoDecoder = null;
    receiver.videoConfigKey = "";
    receiver.gotVideoKeyFrame = false;
    return;
  }
  if (!receiver.gotVideoKeyFrame && payload.chunkType !== "key") {
    return;
  }
  if (receiver.videoDecoder.decodeQueueSize > 8) {
    return;
  }
  const hadVideoKeyFrame = receiver.gotVideoKeyFrame;
  const data = base64urlDecode(payload.bytes);
  const chunk = new codecs.EncodedVideoChunk({
    type: payload.chunkType,
    timestamp: payload.timestamp,
    duration: payload.duration,
    data
  });
  zeroize(data);
  try {
    receiver.videoDecoder.decode(chunk);
  } catch {
    receiver.gotVideoKeyFrame = false;
    return;
  }
  if (payload.chunkType === "key") {
    receiver.gotVideoKeyFrame = true;
    if (!hadVideoKeyFrame) {
      renderChat();
    }
  }
}

function drawDecodedVideoFrame(call: CallRuntime, frame: VideoFrameLike): void {
  const canvas = call.remoteCanvas;
  if (!canvas) {
    frame.close();
    return;
  }
  const width = frame.displayWidth ?? frame.codedWidth ?? CALL_VIDEO_WIDTH;
  const height = frame.displayHeight ?? frame.codedHeight ?? CALL_VIDEO_HEIGHT;
  if (canvas.width !== width || canvas.height !== height) {
    canvas.width = width;
    canvas.height = height;
  }
  const context = canvas.getContext("2d", { alpha: false });
  context?.drawImage(frame, 0, 0, canvas.width, canvas.height);
  frame.close();
}

function decodeCallAudio(call: CallRuntime, payload: CallMediaPayload): void {
  const codecs = webCodecsRuntime();
  if (!codecs.AudioDecoder || !codecs.EncodedAudioChunk || !payload.sampleRate || !payload.numberOfChannels) {
    return;
  }
  const receiver = call.receiver;
  const configKey = `${payload.codec}:${payload.sampleRate}:${payload.numberOfChannels}`;
  try {
    if (!receiver.audioDecoder || receiver.audioConfigKey !== configKey) {
      receiver.audioDecoder?.close();
      receiver.audioDecoder = new codecs.AudioDecoder({
        output: (audioData) => {
          try {
            playDecodedAudio(receiver, audioData);
          } catch {
            audioData.close();
          }
        },
        error: () => undefined
      });
      receiver.audioDecoder.configure({
        codec: payload.codec,
        sampleRate: payload.sampleRate,
        numberOfChannels: payload.numberOfChannels
      });
      receiver.audioConfigKey = configKey;
    }
  } catch {
    receiver.audioDecoder?.close();
    receiver.audioDecoder = null;
    receiver.audioConfigKey = "";
    return;
  }
  if (receiver.audioDecoder.decodeQueueSize > 20) {
    return;
  }
  const data = base64urlDecode(payload.bytes);
  const chunk = new codecs.EncodedAudioChunk({
    type: payload.chunkType,
    timestamp: payload.timestamp,
    duration: payload.duration,
    data
  });
  zeroize(data);
  try {
    receiver.audioDecoder.decode(chunk);
  } catch {
    // Drop malformed audio chunks without breaking the call UI.
  }
}

function playDecodedAudio(receiver: EncodedCallReceiver, audioData: AudioDataLike): void {
  const AudioContextCtor = window.AudioContext;
  if (!AudioContextCtor) {
    audioData.close();
    return;
  }
  receiver.audioContext ??= new AudioContextCtor();
  if (receiver.audioContext.state === "suspended") {
    receiver.audioContext.resume().catch(() => undefined);
  }
  const context = receiver.audioContext;
  const channels = Math.max(1, Math.min(audioData.numberOfChannels, 2));
  const buffer = context.createBuffer(channels, audioData.numberOfFrames, audioData.sampleRate);
  for (let channel = 0; channel < channels; channel += 1) {
    const target = new Float32Array(audioData.numberOfFrames);
    audioData.copyTo(target, { planeIndex: channel, format: "f32-planar" });
    buffer.copyToChannel(target, channel);
  }
  const source = context.createBufferSource();
  source.buffer = buffer;
  source.connect(context.destination);
  source.addEventListener("ended", () => {
    source.disconnect();
  }, { once: true });
  if (receiver.nextAudioTime - context.currentTime > CALL_MAX_AUDIO_QUEUE_DELAY_SEC) {
    receiver.nextAudioTime = context.currentTime + 0.05;
  }
  const startAt = Math.max(context.currentTime + 0.02, receiver.nextAudioTime || 0);
  source.start(startAt);
  receiver.nextAudioTime = startAt + buffer.duration;
  audioData.close();
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

function renderSidebar(state: Runtime): HTMLElement {
  const sidebar = el("aside", { className: "sidebar" });
  const roomHead = el("div", { className: "room-head" }, [
    el("div", { className: "room-title", text: state.roomName }),
    el("div", { className: "safety-line", text: `房间安全码 ${state.safetyCode}` }),
    el("div", {
      className: "safety-line",
      text: state.mode === "two-channel" ? "双通道邀请" : "单链接邀请"
    })
  ]);
  const memberList = el("div", { className: "member-list" }, [renderRoomMember(state)]);
  for (const peer of state.peers.values()) {
    memberList.append(renderPeerMember(state, peer));
  }
  sidebar.append(roomHead, memberList);
  return sidebar;
}

function renderRoomMember(state: Runtime): HTMLElement {
  const item = el("button", {
    className: state.privatePeerId ? "member member-button" : "member member-button active",
    title: "切回房间",
    ariaLabel: "切回房间"
  });
  item.addEventListener("click", () => {
    state.privatePeerId = null;
    state.roomUnread = 0;
    renderChat();
  });
  const badge =
    state.roomUnread > 0
      ? el("span", { className: "badge unread", text: unreadLabel(state.roomUnread) })
      : el("span", { className: "badge ok", text: "房间" });
  item.append(
    el("span", { className: "member-avatar", text: avatarText(state.roomName) }),
    el("span", { className: "member-content" }, [
      el("span", { className: "member-name", text: state.roomName }),
      el("span", { className: "member-subtitle", text: "所有在线成员" })
    ]),
    badge
  );
  return item;
}

function renderPeerMember(state: Runtime, peer: PeerRuntime): HTMLElement {
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
  const badge =
    unread > 0
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
  return item;
}

function renderTopbar(state: Runtime, privatePeer: PeerRuntime | null): HTMLElement {
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
  const actions: Node[] = [];
  const notifications = el("button", {
    className: state.notificationsEnabled || state.soundEnabled ? "secondary active" : "secondary",
    text: notificationButtonText(state)
  });
  notifications.type = "button";
  notifications.addEventListener("click", () => {
    void enableRoomNotifications();
  });
  actions.push(notifications);
  if (privatePeer) {
    const audioCall = el("button", {
      className: "secondary call-action",
      text: "语音",
      title: `语音通话 ${privatePeer.displayName}`,
      ariaLabel: `语音通话 ${privatePeer.displayName}`,
      disabled: Boolean(state.call)
    });
    audioCall.type = "button";
    audioCall.addEventListener("click", () => {
      void startPrivateCall(privatePeer, "audio");
    });
    const videoCall = el("button", {
      className: "secondary call-action",
      text: "视频",
      title: `视频通话 ${privatePeer.displayName}`,
      ariaLabel: `视频通话 ${privatePeer.displayName}`,
      disabled: Boolean(state.call)
    });
    videoCall.type = "button";
    videoCall.addEventListener("click", () => {
      void startPrivateCall(privatePeer, "video");
    });
    actions.push(audioCall, videoCall);
  }
  if (state.inviteLink) {
    const invite = el("button", { className: "secondary", text: "邀请" });
    invite.addEventListener("click", () =>
      showInviteDialog(state.inviteLink!, state.invitePassphrase, state.inviteMode)
    );
    actions.push(invite);
  }
  const security = el("button", { className: "secondary", text: "安全详情" });
  security.addEventListener("click", showSecurityDetails);
  actions.push(security);
  const leave = el("button", { className: "secondary", text: "退出房间" });
  leave.addEventListener("click", () => {
    destroyRuntime();
    renderLogin();
  });
  actions.push(leave);
  return el("header", { className: "topbar" }, [status, el("div", { className: "topbar-actions" }, actions)]);
}

function renderModeBanner(privatePeer: PeerRuntime | null): HTMLElement {
  return el("div", {
    className: privatePeer ? "mode-banner private" : "mode-banner room",
    text: privatePeer ? `私聊模式：消息只发送给 ${privatePeer.displayName}` : "房间模式：消息会发送给所有在线成员"
  });
}

function renderMessageList(state: Runtime): HTMLElement {
  const messages = el("div", { className: "messages" });
  for (const message of state.messages) {
    messages.append(renderMessageRow(message));
  }
  return messages;
}

function renderMessageRow(message: ChatMessage): HTMLElement {
  const row = el("article", {
    className: ["message", message.own ? "own" : "", message.scope].filter(Boolean).join(" ")
  });
  const scopeText =
    message.scope === "private" ? `私聊${message.peerName ? ` · ${message.peerName}` : ""}` : "房间";
  row.append(
    el("div", {
      className: "message-meta",
      text: `${message.author} · ${scopeText} · ${new Date(message.createdAt).toLocaleTimeString()}`
    })
  );
  if (message.kind === "image" && message.imageUrl) {
    row.append(renderImageMessage(message));
  } else if (message.kind === "file" && message.fileBlob) {
    row.append(renderFileMessage(message));
  } else {
    row.append(el("div", { className: "message-text", text: message.text ?? "" }));
  }
  return row;
}

function renderImageMessage(message: ChatMessage): HTMLImageElement {
  const image = el("img", {
    className: "message-image",
    title: message.text ?? "图片"
  });
  image.src = message.imageUrl!;
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
  return image;
}

function renderFileMessage(message: ChatMessage): HTMLElement {
  const fileBlob = message.fileBlob!;
  const fileInfo = el("div", { className: "file-info" }, [
    el("div", { className: "file-name", text: message.fileName ?? "附件" }),
    el("div", {
      className: "file-size",
      text: formatBytes(message.fileSize ?? fileBlob.size)
    })
  ]);
  const download = el("button", { className: "file-download", text: "下载" });
  download.type = "button";
  download.addEventListener("click", () => {
    safeDownload(fileBlob, message.fileName ?? "attachment.bin");
  });
  return el("div", { className: "file-message" }, [el("div", { className: "file-icon", text: "📎" }), fileInfo, download]);
}

function renderComposer(): HTMLElement {
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
    const maxHeight = 112;
    input.style.height = "auto";
    input.style.overflowY = input.scrollHeight > maxHeight ? "auto" : "hidden";
    input.style.height = `${Math.min(input.scrollHeight, maxHeight)}px`;
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
  syncInputHeight();
  return composer;
}

function renderMediaElement(stream: MediaStream, className: string, muted: boolean): HTMLVideoElement | HTMLAudioElement {
  const hasVideo = stream.getVideoTracks().length > 0;
  const media = el(hasVideo ? "video" : "audio", { className });
  media.autoplay = true;
  media.setAttribute("playsinline", "true");
  media.muted = muted;
  media.srcObject = stream;
  return media;
}

function renderCallLayer(state: Runtime): HTMLElement | null {
  const call = state.call;
  if (!call) {
    return null;
  }
  const isIncoming = call.status === "incoming";
  const panel = el("section", { className: ["call-panel", call.media].join(" ") });
  const title = `${call.peerName} · ${mediaLabel(call.media)}${CALL_STATUS_TEXT[call.status]}`;
  const status = el("div", { className: "call-status" }, [
    el("div", { className: "call-avatar", text: avatarText(call.peerName) }),
    el("div", { className: "call-text" }, [
      el("div", { className: "call-title", text: title }),
      el("div", {
        className: "call-subtitle",
        text:
          call.media === "video"
            ? `端到端加密媒体流 · ${CALL_VIDEO_WIDTH}x${CALL_VIDEO_HEIGHT} · ${CALL_VIDEO_FPS}fps`
            : "端到端加密语音流"
      })
    ])
  ]);
  const mediaStage = el("div", { className: "call-stage" });
  if (call.media === "video") {
    const canvas = el("canvas", { className: "call-remote-media call-remote-canvas" }) as HTMLCanvasElement;
    canvas.width = CALL_VIDEO_WIDTH;
    canvas.height = CALL_VIDEO_HEIGHT;
    call.remoteCanvas = canvas;
    mediaStage.append(canvas);
    if (!call.receiver.gotVideoKeyFrame) {
      mediaStage.append(el("div", { className: "call-waiting", text: CALL_STATUS_TEXT[call.status] }));
    }
  } else {
    mediaStage.append(el("div", { className: "call-waiting", text: CALL_STATUS_TEXT[call.status] }));
  }
  if (call.localStream && call.localStream.getTracks().length > 0) {
    mediaStage.append(renderMediaElement(call.localStream, "call-local-media", true));
  }
  const actions = el("div", { className: "call-controls" });
  if (isIncoming) {
    const accept = el("button", { className: "call-control accept", text: "接听" });
    accept.type = "button";
    accept.addEventListener("click", () => {
      void acceptIncomingCall();
    });
    const reject = el("button", { className: "call-control end", text: "拒绝" });
    reject.type = "button";
    reject.addEventListener("click", () => {
      void finishCall("rejected", true);
    });
    actions.append(accept, reject);
  } else {
    const mute = el("button", { className: "call-control", text: call.muted ? "开麦" : "静音" });
    mute.type = "button";
    mute.addEventListener("click", (event) => {
      call.muted = !call.muted;
      call.localStream?.getAudioTracks().forEach((track) => {
        track.enabled = !call.muted;
      });
      if (event.currentTarget instanceof HTMLButtonElement) {
        event.currentTarget.textContent = call.muted ? "开麦" : "静音";
      }
    });
    actions.append(mute);
    if (call.media === "video") {
      const camera = el("button", { className: "call-control", text: call.cameraOff ? "开镜头" : "关镜头" });
      camera.type = "button";
      camera.addEventListener("click", (event) => {
        call.cameraOff = !call.cameraOff;
        call.localStream?.getVideoTracks().forEach((track) => {
          track.enabled = !call.cameraOff;
        });
        if (!call.cameraOff && call.publisher) {
          call.publisher.lastKeyFrameAt = 0;
        }
        if (event.currentTarget instanceof HTMLButtonElement) {
          event.currentTarget.textContent = call.cameraOff ? "开镜头" : "关镜头";
        }
      });
      actions.append(camera);
    }
    const hangup = el("button", { className: "call-control end", text: "挂断" });
    hangup.type = "button";
    hangup.addEventListener("click", () => {
      void finishCall("ended", true);
    });
    actions.append(hangup);
  }
  panel.append(status, mediaStage, actions);
  return panel;
}

function renderChat(): void {
  const state = runtime;
  if (!state) {
    renderLogin();
    return;
  }
  const privatePeer = state.privatePeerId ? state.peers.get(state.privatePeerId) ?? null : null;
  const layout = el("section", { className: "chat-layout" });
  const main = el("section", { className: "chat-main" });
  const messages = renderMessageList(state);
  main.append(renderTopbar(state, privatePeer), renderModeBanner(privatePeer), messages, renderComposer());
  layout.append(renderSidebar(state), main);
  const callLayer = renderCallLayer(state);
  if (callLayer) {
    layout.append(callLayer);
  }
  setApp(layout);
  messages.scrollTop = messages.scrollHeight;
}

function showInviteDialog(
  link: string,
  passphrase: string,
  mode: "single-link" | "two-channel"
): void {
  const backdrop = el("div", { className: "modal-backdrop" });
  const dialog = el("section", { className: "dialog invite-dialog" });
  const notice = el("div", { className: "copy-notice" });
  const qrCanvas = el("canvas", {
    className: "invite-qr-canvas",
    title: "邀请链接二维码",
    ariaLabel: "邀请链接二维码"
  });
  const qrStatus = el("span", { className: "invite-qr-status", text: "正在生成二维码…" });
  const qrCard = el(
    "button",
    {
      className: "invite-qr-card",
      title: "点击复制二维码图片",
      ariaLabel: "复制邀请二维码图片"
    },
    [qrCanvas, qrStatus]
  );
  qrCard.type = "button";
  const linkCard = el(
    "button",
    {
      className: "invite-link-card",
      title: "点击复制邀请链接",
      ariaLabel: "复制邀请链接"
    },
    [
      el("span", { className: "invite-link-text", text: link }),
      el("span", { className: "invite-card-hint", text: "点击复制链接" })
    ]
  );
  linkCard.type = "button";
  const secretCard = el(
    "button",
    {
      className: "invite-secret-card",
      title: "点击复制安全秘钥",
      ariaLabel: "复制安全秘钥"
    },
    [
      el("span", { className: "invite-secret-text", text: passphrase }),
      el("span", { className: "invite-card-hint", text: "点击复制安全秘钥" })
    ]
  );
  secretCard.type = "button";
  const linkSection = el("div", { className: "invite-copy-section" }, [
    el("span", { className: "invite-card-label", text: "链接" }),
    linkCard
  ]);
  const secretSection = el("div", { className: "invite-copy-section" }, [
    el("span", { className: "invite-card-label", text: "安全秘钥" }),
    secretCard
  ]);
  if (mode !== "two-channel") {
    secretSection.hidden = true;
  }
  const showCopyNotice = (message: string, isError = false) => {
    notice.textContent = message;
    notice.className = isError ? "copy-notice error" : "copy-notice ok";
  };
  const close = el("button", {
    className: "dialog-close",
    text: "×",
    title: "关闭",
    ariaLabel: "关闭邀请窗口"
  });
  linkCard.addEventListener("click", () => {
    void navigator.clipboard
      ?.writeText(link)
      .then(() => showCopyNotice("链接已复制"))
      .catch(() => showCopyNotice("复制失败，请手动复制", true));
  });
  secretCard.addEventListener("click", () => {
    void navigator.clipboard
      ?.writeText(passphrase)
      .then(() => showCopyNotice("安全秘钥已复制"))
      .catch(() => showCopyNotice("复制失败，请手动复制", true));
  });
  qrCard.addEventListener("click", () => {
    void copyCanvasPng(qrCanvas)
      .then(() => showCopyNotice("二维码图片已复制"))
      .catch(() => showCopyNotice("当前浏览器不支持复制二维码图片，请复制链接或截图。", true));
  });
  void toCanvas(qrCanvas, link, {
    errorCorrectionLevel: "M",
    margin: 2,
    width: INVITE_QR_SIZE,
    color: {
      dark: "#17212b",
      light: "#ffffff"
    }
  })
    .then(() => {
      qrCanvas.style.width = `${INVITE_QR_SIZE}px`;
      qrCanvas.style.height = `${INVITE_QR_SIZE}px`;
      qrStatus.textContent =
        mode === "two-channel" ? "点击复制二维码；扫码仍需安全秘钥。" : "点击复制二维码；扫码即可加入。";
    })
    .catch(() => {
      qrStatus.textContent = "二维码生成失败，请复制链接分享。";
      qrCanvas.hidden = true;
      qrCard.disabled = true;
    });
  close.type = "button";
  close.addEventListener("click", () => backdrop.remove());
  dialog.append(
    close,
    el("h2", { text: "邀请已生成" }),
    el("p", {
      className: "subtle",
      text:
        mode === "two-channel"
          ? "可以扫码分享链接，但安全秘钥需要通过另一渠道单独发送。"
          : "可以扫码或复制链接分享。"
    }),
    el("div", { className: "invite-share-grid" }, [
      qrCard,
      el("div", { className: mode === "two-channel" ? "invite-copy-stack" : "invite-copy-stack single" }, [
        linkSection,
        secretSection
      ])
    ]),
    notice
  );
  if (mode !== "two-channel") {
    dialog.append(
      el("div", { className: "warning", text: "链接被转发即获得进入能力。" })
    );
  }
  backdrop.append(dialog);
  document.body.append(backdrop);
}

function copyCanvasPng(canvas: HTMLCanvasElement): Promise<void> {
  if (!navigator.clipboard?.write || typeof ClipboardItem === "undefined") {
    return Promise.reject(new Error("clipboard image unsupported"));
  }
  return new Promise<Blob>((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (blob) {
        resolve(blob);
      } else {
        reject(new Error("canvas export failed"));
      }
    }, "image/png");
  }).then((blob) => navigator.clipboard.write([new ClipboardItem({ [blob.type]: blob })]));
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

installNotificationSoundUnlock();
renderLogin();

window.addEventListener("pagehide", destroyRuntime);
