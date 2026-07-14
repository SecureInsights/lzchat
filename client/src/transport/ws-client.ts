import type { JoinMessage, PingMessage, ServerMessage } from "../protocol/types";
import { parseJsonObject, validateServerMessage } from "../protocol/validator";

export type WsClientHandlers = {
  open: () => void;
  close: () => void;
  message: (message: ServerMessage) => void | Promise<void>;
  status: (status: string) => void;
};

export class WsClient {
  #socket: WebSocket | null = null;
  #closed = false;
  #attempt = 0;
  #reconnectTimer: number | null = null;
  #heartbeatTimer: number | null = null;

  constructor(
    private readonly url: string,
    private readonly joinMessage: JoinMessage,
    private readonly handlers: WsClientHandlers
  ) {}

  connect(): void {
    if (this.#reconnectTimer !== null) {
      window.clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
    this.#closed = false;
    this.handlers.status("连接中");
    const socket = new WebSocket(this.url);
    this.#socket = socket;
    socket.addEventListener("open", () => {
      this.#attempt = 0;
      this.handlers.status("已连接");
      this.send(this.joinMessage);
      this.startHeartbeat();
      this.handlers.open();
    });
    socket.addEventListener("message", (event) => {
      if (typeof event.data !== "string") {
        return;
      }
      const parsed = validateServerMessage(parseJsonObject(event.data), this.joinMessage.roomId);
      if (!parsed) {
        return;
      }
      try {
        void Promise.resolve(this.handlers.message(parsed as ServerMessage)).catch(() => {
          this.handlers.status("消息处理失败");
        });
      } catch {
        this.handlers.status("消息处理失败");
      }
    });
    socket.addEventListener("close", () => {
      if (this.#socket === socket) {
        this.#socket = null;
      }
      this.stopHeartbeat();
      this.handlers.close();
      if (!this.#closed) {
        this.handlers.status("已断开，正在重连");
        const delay = Math.min(500 * 2 ** this.#attempt, 5_000);
        this.#attempt += 1;
        this.#reconnectTimer = window.setTimeout(() => {
          this.#reconnectTimer = null;
          if (!this.#closed) {
            this.connect();
          }
        }, delay);
      }
    });
    socket.addEventListener("error", () => {
      this.handlers.status("连接错误");
    });
  }

  send(value: unknown): boolean {
    const socket = this.#socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      return false;
    }
    socket.send(JSON.stringify(value));
    return true;
  }

  isOpen(): boolean {
    return this.#socket?.readyState === WebSocket.OPEN;
  }

  bufferedAmount(): number {
    return this.#socket?.bufferedAmount ?? 0;
  }

  close(): void {
    this.#closed = true;
    this.stopHeartbeat();
    if (this.#reconnectTimer !== null) {
      window.clearTimeout(this.#reconnectTimer);
      this.#reconnectTimer = null;
    }
    this.#socket?.close(1000, "client closing");
    this.#socket = null;
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.#heartbeatTimer = window.setInterval(() => {
      const ping: PingMessage = {
        v: 3,
        t: "ping",
        roomId: this.joinMessage.roomId,
        clientId: this.joinMessage.clientId
      };
      this.send(ping);
    }, 25_000);
  }

  private stopHeartbeat(): void {
    if (this.#heartbeatTimer !== null) {
      window.clearInterval(this.#heartbeatTimer);
      this.#heartbeatTimer = null;
    }
  }
}
