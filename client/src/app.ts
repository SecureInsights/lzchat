import "./style.css";
import { APP_NAME, BUILD_HASH, PROTOCOL_VERSION, wsUrlForRoom } from "./config";
import { base64urlEncode } from "./crypto/base64url";
import { formatSafetyCode, peerFingerprint, roomSafetyCode, rosterDigest } from "./crypto/fingerprint";
import { derivePairSession, generateSessionKeys, type PairSession, type SessionKeys } from "./crypto/handshake";
import { randomBytes } from "./crypto/random";
import { ReceiveRatchet, SendRatchet } from "./crypto/ratchet";
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
import type { CapabilitySet, JoinMessage, MembersMessage, PlainPayload, RelayEnvelope, ServerMessage } from "./protocol/types";
import { validateRelayEnvelope } from "./protocol/validator";
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
  verified: boolean;
  profileSent: boolean;
};

type ChatMessage = {
  id: string;
  own: boolean;
  author: string;
  text: string;
  createdAt: number;
  unverified: boolean;
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
  members: MembersMessage["members"];
  messages: ChatMessage[];
  status: string;
  safetyCode: string;
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

function isTrustedContext(): boolean {
  return (
    window.isSecureContext ||
    window.location.hostname === "127.0.0.1" ||
    window.location.hostname === "localhost" ||
    window.location.hostname === "::1"
  );
}

function makePassphrase(): string {
  return base64urlEncode(randomBytes(18)).match(/.{1,6}/gu)?.join("-") ?? base64urlEncode(randomBytes(18));
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
  runtime?.ws.close();
  runtime = null;

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
  const brand = el("div", { className: "brand" }, [el("span", { className: "brand-mark", text: "S" }), APP_NAME]);
  const title = el("h1", { text: decodedInvite ? "加入临时加密房间" : "创建临时加密房间" });
  const desc = el("p", {
    className: "subtle",
    text: "服务端只看见 roomId、连接状态和密文 envelope。默认使用双通道邀请，链接和口令分开发送。"
  });
  const form = el("div", { className: "form-grid" });
  const notice = el("div");

  const nameInput = el("input", {
    type: "text",
    placeholder: "例如 Alice",
    value: decodedInvite ? "访客" : "Alice"
  });
  const roomInput = el("input", {
    type: "text",
    placeholder: "只在本机显示",
    value: decodedInvite ? "临时房间" : "高保密房间"
  });
  const inviteInput = el("textarea", {
    placeholder: "粘贴邀请链接或 invite token"
  });
  if (pendingInviteToken) {
    inviteInput.value = pendingInviteToken;
  }
  const passInput = el("input", {
    type: "password",
    placeholder: decodedInvite?.mode === "two-channel" ? "输入另一渠道收到的口令" : "创建时留空自动生成"
  });

  const modeButtons = el("div", { className: "segmented" });
  const highButton = el("button", { text: "高保密" });
  const normalButton = el("button", { text: "普通" });
  highButton.classList.add("active");
  highButton.addEventListener("click", () => {
    mode = "two-channel";
    highButton.classList.add("active");
    normalButton.classList.remove("active");
    passInput.disabled = false;
    passInput.placeholder = "留空自动生成独立口令";
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
    el("label", { className: "field" }, ["昵称", nameInput]),
    el("label", { className: "field" }, ["房间显示名", roomInput])
  );

  if (decodedInvite) {
    form.append(el("label", { className: "field" }, ["邀请", inviteInput]));
    if (decodedInvite.mode === "two-channel") {
      form.append(el("label", { className: "field" }, ["独立口令", passInput]));
    }
  } else {
    form.append(el("label", { className: "field" }, ["邀请模式", modeButtons]), el("label", { className: "field" }, ["独立口令", passInput]));
  }

  const action = el("button", { className: "primary", text: decodedInvite ? "加入房间" : "创建房间" });
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
          const secret = await inviteToSecret(invite, invite.mode === "two-channel" ? passInput.value : undefined);
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
        await startRoom({ secret, roomName, displayName, mode });
        showInviteDialog(inviteUrl(shareToken), generatedPassphrase, mode);
      } catch (error) {
        setNotice(notice, error instanceof Error ? error.message : "操作失败", true);
        action.disabled = false;
      }
    })();
  });

  form.append(action, notice);
  if (!isTrustedContext()) {
    form.append(el("div", { className: "warning", text: "当前页面不是 HTTPS，也不是 localhost，已禁用生产聊天入口。" }));
  }
  if (decodedInvite?.mode === "single-link") {
    form.append(el("div", { className: "warning", text: "该邀请为单链接模式，链接包含全部进入秘密。" }));
  }

  panel.append(brand, title, desc, form);
  screen.append(panel);
  setApp(screen);
}

async function startRoom(input: {
  secret: InviteSecret;
  roomName: string;
  displayName: string;
  mode: "single-link" | "two-channel";
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
    members: [],
    messages: [],
    status: "连接中",
    safetyCode: "计算中"
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
      peer.sendRatchet.destroy();
      peer.recvRatchet.destroy();
      state.peers.delete(clientId);
    }
  }
  for (const member of message.members) {
    if (member.clientId === state.clientId) {
      continue;
    }
    const existing = state.peers.get(member.clientId);
    if (existing && existing.sessionPub === member.sessionPub) {
      continue;
    }
    existing?.sendRatchet.destroy();
    existing?.recvRatchet.destroy();
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
    state.peers.set(member.clientId, {
      clientId: member.clientId,
      sessionPub: member.sessionPub,
      displayName: existing?.displayName ?? `临时成员 ${member.clientId.slice(0, 4)}`,
      capabilities: member.capabilities,
      pair,
      sendRatchet: new SendRatchet(pair.sendCK),
      recvRatchet: new ReceiveRatchet(pair.recvCK),
      fingerprint: await peerFingerprint(state.room.roomId, member.sessionPub),
      verified: existing?.verified ?? false,
      profileSent: false
    });
  }
  const digest = await rosterDigest(message.members);
  state.safetyCode = await roomSafetyCode(state.room.rosterKey, digest);
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
    state.ws.send(envelope);
    peer.profileSent = true;
  }
}

async function handleRelay(envelope: RelayEnvelope): Promise<void> {
  const state = runtime;
  if (!state) {
    return;
  }
  const valid = validateRelayEnvelope(envelope, state.room.roomId, undefined, (clientId) => clientId === state.clientId);
  if (!valid || envelope.to !== state.clientId) {
    return;
  }
  const peer = state.peers.get(envelope.from);
  if (!peer) {
    return;
  }
  const payload = await openPayload(envelope, peer.pair.transcriptHash, peer.recvRatchet);
  if (!payload) {
    addSystemMessage("有一条密文未通过验证，已丢弃。");
    return;
  }
  if (payload.type === "profile") {
    peer.displayName = payload.displayName.slice(0, 40) || peer.displayName;
    renderChat();
    return;
  }
  if (payload.type === "text") {
    state.messages.push({
      id: `${envelope.from}:${envelope.seq}`,
      own: false,
      author: peer.displayName,
      text: payload.text,
      createdAt: payload.createdAt,
      unverified: !peer.verified
    });
    renderChat();
  }
}

function addSystemMessage(text: string): void {
  const state = runtime;
  if (!state) {
    return;
  }
  state.messages.push({
    id: `system:${Date.now()}:${Math.random()}`,
    own: false,
    author: "系统",
    text,
    createdAt: Date.now(),
    unverified: false
  });
  renderChat();
}

async function sendTextMessage(text: string): Promise<void> {
  const state = runtime;
  const message = text.trim();
  if (!state || !message) {
    return;
  }
  const payload: PlainPayload = { type: "text", text: message.slice(0, 8_000), createdAt: Date.now() };
  for (const peer of state.peers.values()) {
    const envelope = await sealPayload({
      roomId: state.room.roomId,
      from: state.clientId,
      to: peer.clientId,
      kind: "text",
      transcriptHash: peer.pair.transcriptHash,
      ratchet: peer.sendRatchet,
      payload
    });
    state.ws.send(envelope);
  }
  state.messages.push({
    id: `own:${Date.now()}`,
    own: true,
    author: state.displayName,
    text: payload.text,
    createdAt: payload.createdAt,
    unverified: false
  });
  renderChat();
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
    el("div", { className: "safety-line", text: state.mode === "two-channel" ? "双通道邀请" : "单链接邀请" })
  );
  const memberList = el("div", { className: "member-list" });
  const self = el("div", { className: "member" });
  self.append(el("div", { className: "member-name" }, [state.displayName, el("span", { className: "badge ok", text: "自己" })]));
  self.append(el("div", { className: "safety-line", text: formatSafetyCode(state.clientId.slice(0, 20).padEnd(20, "A")) }));
  memberList.append(self);
  for (const peer of state.peers.values()) {
    const item = el("div", { className: "member" });
    setDataset(item, "clientId", peer.clientId);
    const badge = el("span", { className: peer.verified ? "badge ok" : "badge", text: peer.verified ? "已核对" : "未核对" });
    const verify = el("button", { className: "secondary", text: peer.verified ? "取消核对" : "标记核对" });
    verify.addEventListener("click", () => {
      peer.verified = !peer.verified;
      renderChat();
    });
    item.append(
      el("div", { className: "member-name" }, [peer.displayName, badge]),
      el("div", { className: "safety-line", text: peer.fingerprint }),
      verify
    );
    memberList.append(item);
  }
  sidebar.append(roomHead, memberList);

  const main = el("section", { className: "chat-main" });
  const topbar = el("header", { className: "topbar" });
  const status = el("div", { className: "subtle", text: `${state.status} · ${state.peers.size + 1} 人在线` });
  const security = el("button", { className: "secondary", text: "安全详情" });
  security.addEventListener("click", showSecurityDetails);
  topbar.append(status, security);

  const messages = el("div", { className: "messages" });
  for (const message of state.messages) {
    const row = el("article", { className: message.own ? "message own" : "message" });
    const metaText = `${message.author}${message.unverified ? " · 未核对" : ""} · ${new Date(message.createdAt).toLocaleTimeString()}`;
    row.append(el("div", { className: "message-meta", text: metaText }), el("div", { text: message.text }));
    messages.append(row);
  }

  const composer = el("form", { className: "composer" });
  const input = el("textarea", { placeholder: "输入消息，Enter 发送，Shift+Enter 换行" });
  const send = el("button", { className: "primary", text: "发送" });
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      send.click();
    }
  });
  composer.addEventListener("submit", (event) => {
    event.preventDefault();
    const value = input.value;
    input.value = "";
    void sendTextMessage(value);
  });
  composer.append(input, send);
  main.append(topbar, messages, composer);
  layout.append(sidebar, main);
  setApp(layout);
  messages.scrollTop = messages.scrollHeight;
}

function showInviteDialog(link: string, passphrase: string, mode: "single-link" | "two-channel"): void {
  const backdrop = el("div", { className: "modal-backdrop" });
  const dialog = el("section", { className: "dialog" });
  const linkInput = el("textarea", { value: link });
  const pass = el("input", { type: "text", value: passphrase });
  const close = el("button", { className: "primary", text: "关闭" });
  const copyLink = el("button", { className: "secondary", text: "复制链接" });
  copyLink.addEventListener("click", () => void navigator.clipboard?.writeText(link));
  close.addEventListener("click", () => backdrop.remove());
  dialog.append(
    el("h2", { text: "邀请已生成" }),
    el("p", {
      className: "subtle",
      text: mode === "two-channel" ? "请用两个独立渠道分别发送链接和口令。" : "单链接包含全部进入秘密。"
    }),
    el("label", { className: "field" }, ["链接", linkInput])
  );
  if (mode === "two-channel") {
    const copyPass = el("button", { className: "secondary", text: "复制口令" });
    copyPass.addEventListener("click", () => void navigator.clipboard?.writeText(passphrase));
    dialog.append(el("label", { className: "field" }, ["口令", pass]), el("div", { className: "actions" }, [copyLink, copyPass, close]));
  } else {
    dialog.append(el("div", { className: "warning", text: "链接被转发即获得进入能力。" }), el("div", { className: "actions" }, [copyLink, close]));
  }
  backdrop.append(dialog);
  document.body.append(backdrop);
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
    dialog.append(el("div", { className: "warning", text: "当前房间使用单链接模式，邀请链接包含全部进入秘密。" }));
  }
  for (const peer of state.peers.values()) {
    dialog.append(el("div", { className: "member" }, [el("div", { className: "member-name" }, [peer.displayName]), el("div", { className: "safety-line", text: peer.fingerprint })]));
  }
  dialog.append(el("div", { className: "actions" }, [close]));
  backdrop.append(dialog);
  document.body.append(backdrop);
}

renderLogin();
