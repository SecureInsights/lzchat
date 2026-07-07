import { createHash } from "node:crypto";
import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import {
  CLIENT_TIMEOUT_MS,
  MAX_BAD_MESSAGES,
  MAX_MESSAGES_PER_WINDOW,
  MAX_RELAY_SIZE,
  MAX_ROOM_MEMBERS,
  RATE_WINDOW_MS,
  JOIN_TIMEOUT_MS,
  isValidRoomId,
  parseJsonObject,
  validateJoinMessage,
  validateRelayEnvelope,
  type CapabilitySet,
  type JoinMessage
} from "./validators.js";

type ClientState = {
  socket: WebSocketPeer;
  clientId: string;
  sessionPub: string;
  identityPub?: string;
  capabilities: CapabilitySet;
  seenAt: number;
  joinedAt: number;
  rateWindow: number[];
  badMessages: number;
};

export class WebSocketPeer {
  #buffer = Buffer.alloc(0);
  #closed = false;
  onText: ((text: string) => void) | null = null;
  onClose: (() => void) | null = null;

  constructor(private readonly socket: Duplex) {
    socket.on("data", (chunk: Buffer) => this.accept(chunk));
    socket.on("close", () => this.closeLocal());
    socket.on("error", () => this.closeLocal());
  }

  sendText(text: string): void {
    this.sendFrame(0x1, Buffer.from(text, "utf8"));
  }

  close(code = 1000, reason = ""): void {
    if (this.#closed) {
      return;
    }
    const payload = Buffer.allocUnsafe(2 + Buffer.byteLength(reason));
    payload.writeUInt16BE(code, 0);
    payload.write(reason, 2);
    this.sendFrame(0x8, payload);
    this.#closed = true;
    this.socket.end();
    this.onClose?.();
  }

  private accept(chunk: Buffer): void {
    if (this.#closed) {
      return;
    }
    this.#buffer = Buffer.concat([this.#buffer, chunk]);
    if (this.#buffer.length > MAX_RELAY_SIZE + 14) {
      this.close(1009, "too_big");
      return;
    }
    while (this.#buffer.length >= 2) {
      const first = this.#buffer[0]!;
      const second = this.#buffer[1]!;
      const fin = (first & 0x80) !== 0;
      const opcode = first & 0x0f;
      const masked = (second & 0x80) !== 0;
      let payloadLength = second & 0x7f;
      let offset = 2;
      if (!fin) {
        this.close(1002, "fragmented");
        return;
      }
      if (payloadLength === 126) {
        if (this.#buffer.length < offset + 2) {
          return;
        }
        payloadLength = this.#buffer.readUInt16BE(offset);
        offset += 2;
      } else if (payloadLength === 127) {
        if (this.#buffer.length < offset + 8) {
          return;
        }
        const bigLength = this.#buffer.readBigUInt64BE(offset);
        if (bigLength > BigInt(MAX_RELAY_SIZE)) {
          this.close(1009, "too_big");
          return;
        }
        payloadLength = Number(bigLength);
        offset += 8;
      }
      if (!masked) {
        this.close(1002, "mask_required");
        return;
      }
      if (payloadLength > MAX_RELAY_SIZE || this.#buffer.length < offset + 4 + payloadLength) {
        if (payloadLength > MAX_RELAY_SIZE) {
          this.close(1009, "too_big");
        }
        return;
      }
      const mask = this.#buffer.subarray(offset, offset + 4);
      offset += 4;
      const payload = Buffer.from(this.#buffer.subarray(offset, offset + payloadLength));
      for (let i = 0; i < payload.length; i += 1) {
        payload[i] = payload[i]! ^ mask[i % 4]!;
      }
      this.#buffer = this.#buffer.subarray(offset + payloadLength);
      if (opcode === 0x8) {
        this.closeLocal();
        this.socket.end();
        return;
      }
      if (opcode === 0x9) {
        this.sendFrame(0x0a, payload);
        continue;
      }
      if (opcode !== 0x1) {
        this.close(1003, "text_only");
        return;
      }
      this.onText?.(payload.toString("utf8"));
    }
  }

  private sendFrame(opcode: number, payload: Buffer): void {
    if (this.#closed || !this.socket.writable) {
      return;
    }
    let header: Buffer;
    if (payload.length < 126) {
      header = Buffer.from([0x80 | opcode, payload.length]);
    } else if (payload.length <= 0xffff) {
      header = Buffer.allocUnsafe(4);
      header[0] = 0x80 | opcode;
      header[1] = 126;
      header.writeUInt16BE(payload.length, 2);
    } else {
      header = Buffer.allocUnsafe(10);
      header[0] = 0x80 | opcode;
      header[1] = 127;
      header.writeBigUInt64BE(BigInt(payload.length), 2);
    }
    this.socket.write(Buffer.concat([header, payload]));
  }

  private closeLocal(): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.onClose?.();
  }
}

class Room {
  readonly clients = new Map<string, ClientState>();
  #epoch = 0;
  #sockets = 0;

  constructor(
    readonly roomId: string,
    private readonly onEmpty: (roomId: string) => void
  ) {}

  attach(socket: WebSocketPeer): void {
    let state: ClientState | null = null;
    this.#sockets += 1;
    const joinDeadline = setTimeout(() => {
      if (!state) {
        socket.close(1008, "join_timeout");
      }
    }, JOIN_TIMEOUT_MS);
    const timeout = setInterval(() => {
      if (!state) {
        return;
      }
      if (Date.now() - state.seenAt > CLIENT_TIMEOUT_MS) {
        socket.close(1001, "timeout");
      }
    }, 30_000);
    socket.onText = (text) => {
      if (Buffer.byteLength(text, "utf8") > MAX_RELAY_SIZE) {
        socket.close(1009, "too_big");
        return;
      }
      const parsed = parseJsonObject(text);
      if (!state) {
        const join = validateJoinMessage(parsed, this.roomId);
        if (!join) {
          socket.close(1008, "join_required");
          return;
        }
        state = this.join(socket, join);
        if (state) {
          clearTimeout(joinDeadline);
        }
        return;
      }
      this.onClientMessage(state, parsed);
    };
    socket.onClose = () => {
      clearTimeout(joinDeadline);
      clearInterval(timeout);
      if (state) {
        this.remove(state.clientId, socket);
      }
      this.#sockets = Math.max(0, this.#sockets - 1);
      this.checkEmpty();
    };
  }

  private join(socket: WebSocketPeer, join: JoinMessage): ClientState | null {
    const existing = this.clients.get(join.clientId);
    if (existing) {
      socket.close(1008, "duplicate_client_id");
      return null;
    }
    if (!existing && this.clients.size >= MAX_ROOM_MEMBERS) {
      socket.close(1013, "room_full");
      return null;
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
    this.clients.set(join.clientId, state);
    this.broadcastMembers();
    return state;
  }

  private onClientMessage(state: ClientState, parsed: Record<string, unknown> | null): void {
    state.seenAt = Date.now();
    if (!this.acceptRate(state)) {
      this.bad(state);
      return;
    }
    const relay = validateRelayEnvelope(parsed, this.roomId, state.clientId, (clientId) => this.clients.has(clientId));
    if (!relay) {
      this.bad(state);
      return;
    }
    this.clients.get(relay.to)?.socket.sendText(JSON.stringify(relay));
  }

  private acceptRate(state: ClientState): boolean {
    const now = Date.now();
    state.rateWindow = state.rateWindow.filter((seen) => now - seen < RATE_WINDOW_MS);
    state.rateWindow.push(now);
    return state.rateWindow.length <= MAX_MESSAGES_PER_WINDOW;
  }

  private bad(state: ClientState): void {
    state.badMessages += 1;
    if (state.badMessages >= MAX_BAD_MESSAGES) {
      state.socket.close(1008, "bad_message");
    }
  }

  remove(clientId: string, socket: WebSocketPeer): void {
    const current = this.clients.get(clientId);
    if (current && current.socket === socket) {
      this.clients.delete(clientId);
      this.broadcastMembers();
      this.checkEmpty();
    }
  }

  private checkEmpty(): void {
    if (this.clients.size === 0 && this.#sockets === 0) {
      this.onEmpty(this.roomId);
    }
  }

  private broadcastMembers(): void {
    this.#epoch += 1;
    const members = [...this.clients.values()].map((client) => {
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
    const message = JSON.stringify({ v: 3, t: "members", roomId: this.roomId, epoch: this.#epoch, members });
    for (const client of this.clients.values()) {
      client.socket.sendText(message);
    }
  }
}

export class RelayHub {
  #rooms = new Map<string, Room>();

  handleUpgrade(req: IncomingMessage, socket: Duplex): void {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (url.pathname !== "/ws") {
      socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return;
    }
    const roomId = url.searchParams.get("room");
    if (!isValidRoomId(roomId)) {
      socket.write("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return;
    }
    const key = req.headers["sec-websocket-key"];
    const version = req.headers["sec-websocket-version"];
    if (
      typeof key !== "string" ||
      !isValidWebSocketKey(key) ||
      version !== "13" ||
      !req.headers.upgrade ||
      req.headers.upgrade.toLowerCase() !== "websocket"
    ) {
      socket.write("HTTP/1.1 426 Upgrade Required\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return;
    }
    const accept = createHash("sha1")
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");
    socket.write(
      [
        "HTTP/1.1 101 Switching Protocols",
        "Upgrade: websocket",
        "Connection: Upgrade",
        `Sec-WebSocket-Accept: ${accept}`,
        "\r\n"
      ].join("\r\n")
    );
    const peer = new WebSocketPeer(socket);
    let room = this.#rooms.get(roomId);
    if (!room) {
      room = new Room(roomId, (emptyRoomId) => this.#rooms.delete(emptyRoomId));
      this.#rooms.set(roomId, room);
    }
    room.attach(peer);
  }
}

function isValidWebSocketKey(key: string): boolean {
  try {
    return Buffer.from(key, "base64").length === 16;
  } catch {
    return false;
  }
}
