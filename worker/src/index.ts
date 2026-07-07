import { json, withSecurityHeaders } from "./security-headers";
import {
  CLIENT_TIMEOUT_MS,
  MAX_BAD_MESSAGES,
  MAX_MESSAGES_PER_WINDOW,
  MAX_RELAY_SIZE,
  MAX_ROOM_MEMBERS,
  RATE_WINDOW_MS,
  isValidRoomId,
  parseJsonObject,
  validateJoinMessage,
  validateRelayEnvelope,
  type CapabilitySet,
  type JoinMessage
} from "./validators";

type DurableObjectNamespace = {
  idFromName(name: string): unknown;
  get(id: unknown): { fetch(request: Request): Promise<Response> };
};

type Env = {
  ASSETS: { fetch(request: Request): Promise<Response> };
  CHAT_ROOM: DurableObjectNamespace;
};

type ClientState = {
  socket: WebSocket;
  clientId: string;
  sessionPub: string;
  identityPub?: string;
  capabilities: CapabilitySet;
  seenAt: number;
  joinedAt: number;
  rateWindow: number[];
  badMessages: number;
};

declare const WebSocketPair: {
  new (): { 0: WebSocket; 1: WebSocket };
};

export class ChatRoom {
  #clients = new Map<string, ClientState>();
  #socketToClient = new Map<WebSocket, ClientState>();
  #epoch = 0;
  #roomId: string | null = null;

  fetch(request: Request): Response {
    const url = new URL(request.url);
    const roomId = url.searchParams.get("room");
    if (!isValidRoomId(roomId) || request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return json(400, { error: "bad_request" });
    }
    this.#roomId = roomId;
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1] as WebSocket & { accept: () => void };
    server.accept();
    server.addEventListener("message", (event: MessageEvent) => {
      if (typeof event.data === "string" && event.data.length <= MAX_RELAY_SIZE) {
        this.onMessage(server, event.data);
      } else {
        this.bad(server);
      }
    });
    server.addEventListener("close", () => this.removeSocket(server));
    server.addEventListener("error", () => this.removeSocket(server));
    setTimeout(() => this.checkTimeout(server), CLIENT_TIMEOUT_MS + 1_000);
    return new Response(null, { status: 101, webSocket: client } as ResponseInit & { webSocket: WebSocket });
  }

  private onMessage(socket: WebSocket, text: string): void {
    if (!this.#roomId) {
      socket.close(1011, "not_ready");
      return;
    }
    const parsed = parseJsonObject(text);
    const state = this.#socketToClient.get(socket);
    if (!state) {
      const join = validateJoinMessage(parsed, this.#roomId);
      if (!join) {
        socket.close(1008, "join_required");
        return;
      }
      this.join(socket, join);
      return;
    }
    state.seenAt = Date.now();
    if (!this.acceptRate(state)) {
      this.bad(socket);
      return;
    }
    const relay = validateRelayEnvelope(parsed, this.#roomId, state.clientId, (clientId) => this.#clients.has(clientId));
    if (!relay) {
      this.bad(socket);
      return;
    }
    this.#clients.get(relay.to)?.socket.send(JSON.stringify(relay));
  }

  private join(socket: WebSocket, join: JoinMessage): void {
    const existing = this.#clients.get(join.clientId);
    if (!existing && this.#clients.size >= MAX_ROOM_MEMBERS) {
      socket.close(1013, "room_full");
      return;
    }
    const state: ClientState = {
      socket,
      clientId: join.clientId,
      sessionPub: join.sessionPub,
      capabilities: join.capabilities,
      seenAt: Date.now(),
      joinedAt: Date.now(),
      rateWindow: [],
      badMessages: 0
    };
    if (join.identityPub) {
      state.identityPub = join.identityPub;
    }
    this.#clients.set(join.clientId, state);
    this.#socketToClient.set(socket, state);
    if (existing && existing.socket !== socket) {
      existing.socket.close(4000, "replaced");
    }
    this.broadcastMembers();
  }

  private acceptRate(state: ClientState): boolean {
    const now = Date.now();
    state.rateWindow = state.rateWindow.filter((seen) => now - seen < RATE_WINDOW_MS);
    state.rateWindow.push(now);
    return state.rateWindow.length <= MAX_MESSAGES_PER_WINDOW;
  }

  private bad(socket: WebSocket): void {
    const state = this.#socketToClient.get(socket);
    if (!state) {
      socket.close(1008, "bad_message");
      return;
    }
    state.badMessages += 1;
    if (state.badMessages >= MAX_BAD_MESSAGES) {
      socket.close(1008, "bad_message");
    }
  }

  private removeSocket(socket: WebSocket): void {
    const state = this.#socketToClient.get(socket);
    this.#socketToClient.delete(socket);
    if (!state) {
      return;
    }
    const current = this.#clients.get(state.clientId);
    if (current && current.socket === socket) {
      this.#clients.delete(state.clientId);
      this.broadcastMembers();
    }
  }

  private broadcastMembers(): void {
    if (!this.#roomId) {
      return;
    }
    this.#epoch += 1;
    const members = [...this.#clients.values()].map((client) => {
      const member: {
        clientId: string;
        sessionPub: string;
        identityPub?: string;
        capabilities: CapabilitySet;
      } = {
        clientId: client.clientId,
        sessionPub: client.sessionPub,
        capabilities: client.capabilities
      };
      if (client.identityPub) {
        member.identityPub = client.identityPub;
      }
      return member;
    });
    const message = JSON.stringify({ v: 3, t: "members", roomId: this.#roomId, epoch: this.#epoch, members });
    for (const client of this.#clients.values()) {
      client.socket.send(message);
    }
  }

  private checkTimeout(socket: WebSocket): void {
    const state = this.#socketToClient.get(socket);
    if (!state) {
      return;
    }
    if (Date.now() - state.seenAt > CLIENT_TIMEOUT_MS) {
      socket.close(1001, "timeout");
      return;
    }
    setTimeout(() => this.checkTimeout(socket), 30_000);
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/api/health") {
      return json(200, { ok: true, protocol: 3 });
    }
    if (url.pathname.startsWith("/api/")) {
      return json(404, { error: "not_found" });
    }
    if (url.pathname === "/ws") {
      const roomId = url.searchParams.get("room");
      if (!isValidRoomId(roomId)) {
        return json(400, { error: "bad_room" });
      }
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return json(426, { error: "upgrade_required" });
      }
      const id = env.CHAT_ROOM.idFromName(roomId);
      return env.CHAT_ROOM.get(id).fetch(request);
    }
    return withSecurityHeaders(await env.ASSETS.fetch(request));
  }
};
